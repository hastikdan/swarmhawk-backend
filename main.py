"""
SwarmHawk Backend API
=====================
FastAPI backend for the CEE Cyber Intelligence SaaS platform.

Endpoints:
  GET  /domains              — list user's domains
  POST /domains              — add domain (free)
  GET  /domains/{id}/report  — get scan report (free = partial, paid = full)
  POST /checkout             — create Stripe checkout session ($10)
  POST /webhook              — Stripe webhook → mark domain as paid
  GET  /admin/stats          — admin overview

Run locally:
  pip install fastapi uvicorn supabase stripe httpx
  uvicorn main:app --reload --port 8000
"""

import os
import json
import hmac
import hashlib
import secrets
import httpx
import stripe
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from supabase import create_client, Client

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL        = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY", "")        # anon/service key
STRIPE_SECRET_KEY   = os.getenv("STRIPE_SECRET_KEY", "")   # sk_live_... or sk_test_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")  # whsec_...
STRIPE_PRICE_ID     = os.getenv("STRIPE_PRICE_ID", "")     # price_... from Stripe dashboard
FRONTEND_URL        = os.getenv("FRONTEND_URL", "https://hastikdan.github.io/cee-scanner")
ADMIN_EMAIL         = os.getenv("ADMIN_EMAIL", "hastikdan@gmail.com")  # super-admin
RESEND_API_KEY      = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL          = os.getenv("OUTREACH_FROM", "security@swarmhawk.eu")
SITE_URL            = os.getenv("SITE_URL", "https://hastikdan.github.io/cee-scanner")

stripe.api_key = STRIPE_SECRET_KEY

# ── Supabase client ───────────────────────────────────────────────────────────

db: Client = None

def get_db() -> Client:
    global db
    if db is None:
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise HTTPException(503, "Database not configured — set SUPABASE_URL and SUPABASE_KEY on Render")
        try:
            db = create_client(SUPABASE_URL, SUPABASE_KEY)
        except Exception as e:
            raise HTTPException(503, f"Database connection failed: {str(e)[:200]}")
    return db

# ── App ───────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager

SCANNER_AVAILABLE = False  # set True at startup if cee_scanner imports OK

@asynccontextmanager
async def lifespan(app):
    global SCANNER_AVAILABLE
    # Check scanner is importable
    try:
        from cee_scanner.checks import scan_domain
        SCANNER_AVAILABLE = True
        print("✓ cee_scanner loaded OK")
    except Exception as e:
        SCANNER_AVAILABLE = False
        print(f"✗ cee_scanner NOT available: {e}")
        print("  → Deploy cee_scanner/ directory into backend repo root")
    # Start daily outreach scan scheduler on startup
    try:
        from outreach import start_scheduler
        _scheduler = start_scheduler()
    except Exception as e:
        print(f"Scheduler init failed: {e}")
    yield

app = FastAPI(title="SwarmHawk API", version="2.0.0", lifespan=lifespan)

# CORS must be added BEFORE any exception handlers or routers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount outreach router
try:
    from outreach import router as outreach_router
    app.include_router(outreach_router)
    print("Outreach router mounted at /outreach")
except Exception as e:
    print(f"Outreach router failed to load: {e}")


# ── Models ────────────────────────────────────────────────────────────────────

class AddDomainRequest(BaseModel):
    domain: str
    country: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    domain: str = ""        # optional first domain at signup

class LoginRequest(BaseModel):
    email: str
    password: str

class CheckoutRequest(BaseModel):
    domain_id: str
    domain: str
    plan: str = "one_time"   # "one_time" ($10) | "annual" ($50/year subscription)

# ── Auth helpers ──────────────────────────────────────────────────────────────

def get_user_from_header(authorization: str) -> dict:
    """Look up session token in sessions table and return user info."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = authorization.split(" ")[1]
    try:
        db = get_db()
        result = db.table("sessions").select("user_id").eq("token", token).execute()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database error: {str(e)[:200]}")
    if not result.data:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    user_id = result.data[0]["user_id"]
    return {"sub": user_id}


def hash_password(password: str) -> str:
    """SHA-256 + salt. Good enough for MVP; swap for bcrypt in production."""
    salt = hashlib.sha256(os.getenv("SECRET_SALT", "swarmhawk-salt").encode()).hexdigest()[:16]
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


def make_session(user_id: str) -> str:
    token = hashlib.sha256(f"{user_id}:{secrets.token_hex(16)}".encode()).hexdigest()
    db = get_db()
    db.table("sessions").insert({
        "user_id":    user_id,
        "token":      token,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()
    return token


def is_admin(user_id: str) -> bool:
    if not ADMIN_EMAIL:
        return False
    db = get_db()
    r = db.table("users").select("email").eq("id", user_id).execute()
    return bool(r.data and r.data[0]["email"] == ADMIN_EMAIL)


def require_admin(authorization: str) -> str:
    user = get_user_from_header(authorization)
    if not is_admin(user["sub"]):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user["sub"]

# ── Email confirmation helper ─────────────────────────────────────────────────

def send_confirmation_email(to_email: str, name: str, token: str):
    """Send signup confirmation email via Resend."""
    if not RESEND_API_KEY:
        print(f"[auth] RESEND_API_KEY not set — skipping confirmation email to {to_email}")
        return
    confirm_url = f"{SITE_URL}?confirm={token}"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0a0a0a;color:#fff;padding:40px;border-radius:8px">
      <div style="margin-bottom:28px">
        <span style="font-family:monospace;font-size:18px;font-weight:700;color:#cbff00">●SWARMHAWK</span>
      </div>
      <h2 style="color:#fff;margin-bottom:8px">Confirm your email</h2>
      <p style="color:#888;line-height:1.6;margin-bottom:24px">
        Hi {name}, welcome to SwarmHawk. Click below to confirm your email address and activate your account.
      </p>
      <a href="{confirm_url}" style="display:inline-block;background:#cbff00;color:#000;font-family:monospace;font-weight:700;font-size:13px;padding:12px 28px;border-radius:5px;text-decoration:none">
        CONFIRM EMAIL →
      </a>
      <p style="color:#555;font-size:12px;margin-top:28px;line-height:1.5">
        This link expires in 24 hours. If you didn't create an account, ignore this email.<br>
        SwarmHawk · CEE Cybersecurity Intelligence
      </p>
    </div>
    """
    try:
        import httpx as _httpx
        _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from":    f"SwarmHawk <{FROM_EMAIL}>",
                "to":      [to_email],
                "subject": "Confirm your SwarmHawk account",
                "html":    html,
            },
            timeout=10,
        )
        print(f"[auth] Confirmation email sent to {to_email}")
    except Exception as e:
        print(f"[auth] Failed to send confirmation email: {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0", "scanner": SCANNER_AVAILABLE}


@app.get("/debug-config")
def debug_config():
    """Temporary: show env var config (no secrets exposed)."""
    url = SUPABASE_URL or ""
    key = SUPABASE_KEY or ""
    return {
        "url_set": bool(url),
        "url_preview": url[:30] if url else "",
        "key_set": bool(key),
        "key_length": len(key),
        "key_preview": key[:10] if key else "",
        "key_suffix": key[-6:] if len(key) > 6 else "",
    }


# ── Email / password auth ─────────────────────────────────────────────────────

@app.post("/auth/register")
async def register(body: RegisterRequest, background_tasks: BackgroundTasks):
    """Create account with username + email + password."""
    import re as _re
    if not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', body.email):
        raise HTTPException(400, "Invalid email address")
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if not body.username.strip():
        raise HTTPException(400, "Username required")

    try:
        db = get_db()
        existing = db.table("users").select("id").eq("email", body.email.lower()).execute()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"Database error: {str(e)[:200]}")

    if existing.data:
        raise HTTPException(409, "Email already registered — please sign in")

    # Create user
    try:
        result = db.table("users").insert({
            "google_id":     f"email:{body.email.lower()}",
            "email":         body.email.lower(),
            "name":          body.username.strip(),
            "password_hash": hash_password(body.password),
            "auth_type":     "email",
            "created_at":    datetime.now(timezone.utc).isoformat(),
            "last_login":    datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        err = str(e)
        if "password_hash" in err or "auth_type" in err or "column" in err.lower():
            raise HTTPException(500,
                "Database schema missing columns. Run in Supabase SQL Editor: "
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text; "
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_type text DEFAULT 'google';"
            )
        raise HTTPException(500, f"Could not create user: {err[:200]}")

    user = result.data[0]
    session_token = make_session(user["id"])

    # Generate verification token and send confirmation email
    verification_token = secrets.token_urlsafe(32)
    try:
        db.table("users").update({
            "verification_token": verification_token,
            "email_verified":     False,
        }).eq("id", user["id"]).execute()
    except Exception:
        pass  # columns may not exist yet — email still works, just unverified
    background_tasks.add_task(
        send_confirmation_email, body.email.lower(), body.username.strip(), verification_token
    )

    # Add first domain if provided
    first_domain = None
    if body.domain:
        domain = body.domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        if _re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
            dom_result = db.table("domains").insert({
                "user_id":    user["id"],
                "domain":     domain,
                "country":    "EU",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
            first_domain = dom_result.data[0]
            background_tasks.add_task(run_scan_background, first_domain["id"], domain)

    return {
        "user": {
            "id":       user["id"],
            "email":    body.email.lower(),
            "name":     body.username.strip(),
            "avatar":   "",
            "is_admin": is_admin(user["id"]),
        },
        "session_token": session_token,
        "first_domain":  first_domain,
    }


@app.post("/auth/login")
async def login_email(body: LoginRequest):
    """Sign in with email + password."""
    try:
        db = get_db()
        result = db.table("users").select("*").eq("email", body.email.lower()).execute()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"Database error: {str(e)[:200]}")

    if not result.data:
        raise HTTPException(401, "No account found with that email")

    user = result.data[0]
    if user.get("password_hash") != hash_password(body.password):
        raise HTTPException(401, "Incorrect password")

    # Update last login
    db.table("users").update({
        "last_login": datetime.now(timezone.utc).isoformat()
    }).eq("id", user["id"]).execute()

    session_token = make_session(user["id"])
    return {
        "user": {
            "id":       user["id"],
            "email":    user["email"],
            "name":     user["name"] or user["email"],
            "avatar":   user.get("avatar", ""),
            "is_admin": is_admin(user["id"]),
        },
        "session_token": session_token,
    }


# ── Admin endpoints ───────────────────────────────────────────────────────────

@app.get("/auth/verify-email")
def verify_email(token: str):
    """Confirm email address from link in confirmation email."""
    if not token:
        raise HTTPException(400, "Missing token")
    db = get_db()
    result = db.table("users")        .select("id,email,name")        .eq("verification_token", token)        .execute()
    if not result.data:
        raise HTTPException(400, "Invalid or expired confirmation link")
    user = result.data[0]
    db.table("users").update({
        "email_verified":     True,
        "verification_token": None,
    }).eq("id", user["id"]).execute()
    # Redirect to site with success flag
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"{SITE_URL}?verified=1", status_code=302)


@app.get("/admin/users")
def admin_users(
    page: int = 1,
    per_page: int = 50,
    authorization: str = Header(None),
):
    """Full user list with domain counts and last login. Admin only."""
    require_admin(authorization)
    db = get_db()

    offset = (page - 1) * per_page
    users = db.table("users").select("*").order("created_at", desc=True).range(offset, offset + per_page - 1).execute()
    total = db.table("users").select("id", count="exact").execute()

    rows = []
    for u in (users.data or []):
        doms = db.table("domains").select("id", count="exact").eq("user_id", u["id"]).execute()
        paid = db.table("purchases").select("id", count="exact").eq("user_id", u["id"]).execute()
        rows.append({
            "id":           u["id"],
            "email":        u["email"],
            "name":         u.get("name", ""),
            "auth_type":    u.get("auth_type", "google"),
            "domain_count": doms.count or 0,
            "paid_domains": paid.count or 0,
            "created_at":   u.get("created_at", ""),
            "last_login":   u.get("last_login", ""),
        })

    return {"users": rows, "total": total.count, "page": page, "per_page": per_page}


@app.get("/admin/domains")
def admin_domains(
    page: int = 1,
    per_page: int = 50,
    authorization: str = Header(None),
):
    """All domains across all users with scan status. Admin only."""
    require_admin(authorization)
    db = get_db()

    offset = (page - 1) * per_page
    domains = db.table("domains").select("*, users(email,name)").order("created_at", desc=True).range(offset, offset + per_page - 1).execute()
    total   = db.table("domains").select("id", count="exact").execute()

    rows = []
    for d in (domains.data or []):
        # Get latest scan
        scan = db.table("scans").select("risk_score,scanned_at").eq("domain_id", d["id"]).order("scanned_at", desc=True).limit(1).execute()
        paid = db.table("purchases").select("id").eq("domain_id", d["id"]).execute()
        rows.append({
            "id":          d["id"],
            "domain":      d["domain"],
            "country":     d.get("country", ""),
            "user_email":  d.get("users", {}).get("email", "") if d.get("users") else "",
            "user_name":   d.get("users", {}).get("name", "") if d.get("users") else "",
            "risk_score":  scan.data[0]["risk_score"] if scan.data else None,
            "scanned_at":  scan.data[0]["scanned_at"] if scan.data else None,
            "paid":        bool(paid.data),
            "created_at":  d.get("created_at", ""),
        })

    return {"domains": rows, "total": total.count, "page": page, "per_page": per_page}


@app.get("/admin/stats")
def admin_stats(authorization: str = Header(None)):
    """Full platform stats. Admin only."""
    require_admin(authorization)
    db = get_db()

    from datetime import timedelta

    users     = db.table("users").select("id,created_at,auth_type").execute()
    domains   = db.table("domains").select("id,domain,created_at").execute()
    purchases = db.table("purchases").select("amount_usd,paid_at").execute()
    # Fetch scans with risk data and checks for deeper metrics
    scans     = db.table("scans").select("id,domain_id,risk_score,critical,warnings,checks,scanned_at").order("scanned_at", desc=True).limit(500).execute()

    now = datetime.now(timezone.utc)

    def within_days(rows, field, days):
        cutoff = (now - timedelta(days=days)).isoformat()
        return sum(1 for r in rows if r.get(field, "") >= cutoff)

    revenue      = sum(p.get("amount_usd", 0) or 0 for p in purchases.data)
    email_users  = sum(1 for u in users.data if u.get("auth_type") == "email")

    # Latest scan per domain
    domain_latest: dict[str, dict] = {}
    for s in scans.data:
        did = s.get("domain_id")
        if did and did not in domain_latest:
            domain_latest[did] = s

    scanned_domains = list(domain_latest.values())
    scores = [s.get("risk_score") or 0 for s in scanned_domains]
    avg_risk   = round(sum(scores) / len(scores), 1) if scores else 0
    critical_d = sum(1 for s in scanned_domains if (s.get("risk_score") or 0) >= 70)
    warning_d  = sum(1 for s in scanned_domains if 30 <= (s.get("risk_score") or 0) < 70)
    clean_d    = sum(1 for s in scanned_domains if (s.get("risk_score") or 0) < 30)

    # Check-type firing frequency across latest scans
    check_counts: dict[str, dict] = {}
    for s in scanned_domains:
        raw = s.get("checks", []) or []
        if isinstance(raw, str):
            try: raw = json.loads(raw)
            except: raw = []
        for c in (raw if isinstance(raw, list) else []):
            name = c.get("check", "unknown")
            st   = c.get("status", "ok")
            if name not in check_counts:
                check_counts[name] = {"critical": 0, "warning": 0, "ok": 0, "error": 0}
            check_counts[name][st] = check_counts[name].get(st, 0) + 1

    # Top 10 riskiest domains
    domain_map = {d["id"]: d["domain"] for d in domains.data}
    top_risky = sorted(
        [{"domain": domain_map.get(s["domain_id"], "?"), "risk_score": s.get("risk_score") or 0,
          "critical": s.get("critical") or 0, "warnings": s.get("warnings") or 0,
          "scanned_at": s.get("scanned_at", "")}
         for s in scanned_domains],
        key=lambda x: x["risk_score"], reverse=True
    )[:10]

    # Recent 20 scans for activity feed
    recent_scans = []
    for s in scans.data[:20]:
        recent_scans.append({
            "domain":     domain_map.get(s.get("domain_id", ""), "?"),
            "risk_score": s.get("risk_score") or 0,
            "critical":   s.get("critical") or 0,
            "warnings":   s.get("warnings") or 0,
            "scanned_at": s.get("scanned_at", ""),
        })

    return {
        "users": {
            "total":      len(users.data),
            "google":     len(users.data) - email_users,
            "email":      email_users,
            "new_7d":     within_days(users.data, "created_at", 7),
            "new_30d":    within_days(users.data, "created_at", 30),
        },
        "domains": {
            "total":      len(domains.data),
            "scanned":    len(scanned_domains),
            "new_7d":     within_days(domains.data, "created_at", 7),
            "new_30d":    within_days(domains.data, "created_at", 30),
        },
        "revenue": {
            "total_eur":   round(revenue, 2),
            "total_sales": len(purchases.data),
            "new_7d":      within_days(purchases.data, "paid_at", 7),
        },
        "scans": {
            "total":       len(scans.data),
            "last_7d":     within_days(scans.data, "scanned_at", 7),
            "last_24h":    within_days(scans.data, "scanned_at", 1),
        },
        "risk": {
            "avg_score":   avg_risk,
            "critical":    critical_d,
            "warning":     warning_d,
            "clean":       clean_d,
        },
        "check_breakdown": check_counts,
        "top_risky":       top_risky,
        "recent_scans":    recent_scans,
    }


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, authorization: str = Header(None)):
    """Delete a user and all their data. Admin only."""
    require_admin(authorization)
    db = get_db()
    db.table("users").delete().eq("id", user_id).execute()
    return {"deleted": user_id}


@app.post("/admin/users/{user_id}/rescan-all")
def admin_rescan_user(user_id: str, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Force re-scan all domains for a user. Admin only."""
    require_admin(authorization)
    db = get_db()
    doms = db.table("domains").select("id,domain").eq("user_id", user_id).execute()
    for d in (doms.data or []):
        background_tasks.add_task(run_scan_background, d["id"], d["domain"])
    return {"queued": len(doms.data or [])}


@app.get("/me")
def get_me(authorization: str = Header(None)):
    """Return current user info including is_admin flag."""
    user = get_user_from_header(authorization)
    db   = get_db()
    result = db.table("users").select("*").eq("id", user["sub"]).execute()
    if not result.data:
        raise HTTPException(404, "User not found")
    u = result.data[0]
    return {
        "id":       u["id"],
        "email":    u["email"],
        "name":     u.get("name", ""),
        "avatar":   u.get("avatar", ""),
        "is_admin": is_admin(u["id"]),
        "auth_type": u.get("auth_type", "google"),
    }


class UpdateProfileRequest(BaseModel):
    name:             str | None = None
    email:            str | None = None
    current_password: str | None = None
    new_password:     str | None = None


@app.patch("/me")
def update_profile(body: UpdateProfileRequest, authorization: str = Header(None)):
    """Update current user's name, email, and/or password."""
    import re as _re
    user = get_user_from_header(authorization)
    db   = get_db()

    row = db.table("users").select("*").eq("id", user["sub"]).execute()
    if not row.data:
        raise HTTPException(404, "User not found")
    u = row.data[0]

    updates: dict = {}

    # ── Name ────────────────────────────────────────────────────────────────
    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(400, "Name cannot be empty")
        updates["name"] = name

    # ── Email ────────────────────────────────────────────────────────────────
    if body.email is not None:
        email = body.email.strip().lower()
        if not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            raise HTTPException(400, "Invalid email address")
        if email != u["email"]:
            taken = db.table("users").select("id").eq("email", email).execute()
            if taken.data:
                raise HTTPException(409, "Email already in use by another account")
            updates["email"] = email

    # ── Password ─────────────────────────────────────────────────────────────
    if body.new_password is not None:
        if len(body.new_password) < 6:
            raise HTTPException(400, "New password must be at least 6 characters")
        # Require current password to set a new one
        if not body.current_password:
            raise HTTPException(400, "Current password required to set a new password")
        if u.get("password_hash") != hash_password(body.current_password):
            raise HTTPException(401, "Current password is incorrect")
        updates["password_hash"] = hash_password(body.new_password)

    if not updates:
        raise HTTPException(400, "Nothing to update")

    db.table("users").update(updates).eq("id", user["sub"]).execute()

    # Return fresh user record
    fresh = db.table("users").select("id,email,name,avatar,auth_type,created_at").eq("id", user["sub"]).execute()
    u2 = fresh.data[0]
    return {
        "id":       u2["id"],
        "email":    u2["email"],
        "name":     u2.get("name", ""),
        "avatar":   u2.get("avatar", ""),
        "auth_type": u2.get("auth_type", ""),
        "created_at": u2.get("created_at", ""),
    }


@app.delete("/me")
def delete_account(authorization: str = Header(None)):
    """Delete the current user's account and all associated data."""
    user = get_user_from_header(authorization)
    db   = get_db()
    uid  = user["sub"]
    # Delete all user data in order (domains cascade to scans/purchases via FK)
    domains = db.table("domains").select("id").eq("user_id", uid).execute()
    for d in (domains.data or []):
        db.table("scans").delete().eq("domain_id", d["id"]).execute()
        db.table("purchases").delete().eq("domain_id", d["id"]).execute()
    db.table("domains").delete().eq("user_id", uid).execute()
    db.table("sessions").delete().eq("user_id", uid).execute()
    db.table("users").delete().eq("id", uid).execute()
    return {"deleted": True}


@app.get("/domains")
def list_domains(authorization: str = Header(None)):
    """List all domains for the logged-in user."""
    user = get_user_from_header(authorization)
    db = get_db()

    domains = db.table("domains")\
        .select("*, scans(*), purchases(*)")\
        .eq("user_id", user["sub"])\
        .order("created_at", desc=True)\
        .execute()

    result = []
    for d in domains.data:
        latest_scan = max(d.get("scans", []), key=lambda s: s["scanned_at"], default=None)
        is_paid = any(p.get("paid_at") for p in d.get("purchases", []))
        # "scanning" if added within last 10 min and no scan yet
        created_at = d.get("created_at", "")
        is_new = False
        if created_at and not latest_scan:
            try:
                from dateutil import parser as dtparse
                age = (datetime.now(timezone.utc) - dtparse.parse(created_at)).total_seconds()
                is_new = age < 600
            except Exception:
                pass
        status = "scanning" if is_new else ("active" if latest_scan else "pending")

        result.append({
            "id":          d["id"],
            "domain":      d["domain"],
            "country":     d["country"],
            "added":       d["created_at"],
            "status":      status,
            "paid":        is_paid,
            "risk_score":  latest_scan["risk_score"] if latest_scan else None,
            "scanned_at":  latest_scan["scanned_at"] if latest_scan else None,
            "scan_history": [
                {"date": s["scanned_at"], "risk": s["risk_score"]}
                for s in sorted(d.get("scans", []), key=lambda s: s["scanned_at"])
            ],
        })

    return {"domains": result}


@app.post("/domains")
def add_domain(body: AddDomainRequest, background_tasks: BackgroundTasks,
               authorization: str = Header(None)):
    """Add a domain for free scanning."""
    user = get_user_from_header(authorization)

    # Validate domain format
    import re
    if not re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', body.domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    db = get_db()

    # Check if user already added this domain
    existing = db.table("domains")\
        .select("id")\
        .eq("user_id", user["sub"])\
        .eq("domain", body.domain.lower())\
        .execute()

    if existing.data:
        raise HTTPException(status_code=409, detail="Domain already added")

    # Insert domain
    result = db.table("domains").insert({
        "user_id":    user["sub"],
        "domain":     body.domain.lower(),
        "country":    body.country,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

    domain_record = result.data[0]

    # Queue scan in background
    background_tasks.add_task(run_scan_background, domain_record["id"], body.domain)

    return {
        "id":     domain_record["id"],
        "domain": body.domain,
        "status": "scanning",
        "message": "Domain added — scan starting now",
    }


@app.delete("/domains/{domain_id}")
def delete_domain(domain_id: str, authorization: str = Header(None)):
    """Delete a domain and all its scans."""
    user = get_user_from_header(authorization)
    db = get_db()
    domain = db.table("domains").select("id").eq("id", domain_id).eq("user_id", user["sub"]).execute()
    if not domain.data:
        raise HTTPException(404, "Domain not found")
    db.table("domains").delete().eq("id", domain_id).execute()
    return {"deleted": domain_id}


@app.post("/domains/{domain_id}/rescan")
def rescan_domain(domain_id: str, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Trigger a fresh scan for an existing domain."""
    user = get_user_from_header(authorization)
    db = get_db()
    domain = db.table("domains").select("id,domain").eq("id", domain_id).eq("user_id", user["sub"]).execute()
    if not domain.data:
        raise HTTPException(404, "Domain not found")
    d = domain.data[0]
    background_tasks.add_task(run_scan_background, d["id"], d["domain"])
    return {"status": "scanning", "message": f"Rescan started for {d['domain']}"}


@app.get("/domains/{domain_id}/report")
def get_report(domain_id: str, authorization: str = Header(None)):
    """
    Get scan report for a domain.
    Free users get threat intel + 3 config checks.
    Paid users get the full 15-check report + AI analysis.
    """
    user = get_user_from_header(authorization)
    db = get_db()

    # Get domain + latest scan + purchase status
    domain = db.table("domains")\
        .select("*, scans(*), purchases(*)")\
        .eq("id", domain_id)\
        .eq("user_id", user["sub"])\
        .single()\
        .execute()

    if not domain.data:
        raise HTTPException(status_code=404, detail="Domain not found")

    d = domain.data
    scans = sorted(d.get("scans", []), key=lambda s: s["scanned_at"], reverse=True)
    latest = scans[0] if scans else None
    is_paid = any(p.get("paid_at") for p in d.get("purchases", []))

    if not latest:
        return {"status": "pending", "message": "Scan in progress"}

    # Safely decode checks — may be a list (jsonb) or string (old bug: json.dumps was used)
    raw_checks = latest.get("checks", [])
    if isinstance(raw_checks, str):
        try:
            raw_checks = json.loads(raw_checks)
        except Exception:
            raw_checks = []
    checks = raw_checks if isinstance(raw_checks, list) else []

    # Free = core checks visible; paid = all checks including AI summary
    FREE_CHECKS = {"urlhaus", "safebrowsing", "virustotal", "spamhaus", "breach",
                   "whois", "email_security", "ssl", "headers", "dns",
                   "sast", "sca", "dast", "iac"}

    if is_paid:
        visible_checks = checks
    else:
        visible_checks = [c for c in checks if c.get("check") in FREE_CHECKS]

    non_ai = [c for c in visible_checks if c.get("check") != "ai_summary"]
    return {
        "domain":      d["domain"],
        "risk_score":  latest["risk_score"],
        "scanned_at":  latest["scanned_at"],
        "paid":        is_paid,
        "checks":      visible_checks,
        "critical":    sum(1 for c in non_ai if c.get("status") == "critical"),
        "warnings":    sum(1 for c in non_ai if c.get("status") == "warning"),
        "locked_count": len(checks) - len(visible_checks) if not is_paid else 0,
    }


# ── PDF report generation ──────────────────────────────────────────────────────

def _generate_pdf(domain: str, risk_score: int, scanned_at: str, checks: list) -> bytes:
    """Build a PDF security report and return raw bytes."""
    from fpdf import FPDF

    STATUS_EMOJI = {"critical": "CRITICAL", "warning": "WARNING", "ok": "OK", "error": "ERROR"}
    STATUS_COLOR = {
        "critical": (192, 57,  43),
        "warning":  (212, 133, 10),
        "ok":       (26,  122, 74),
        "error":    (100, 100, 100),
    }

    non_ai = [c for c in checks if c.get("check") != "ai_summary"]
    criticals = sum(1 for c in non_ai if c.get("status") == "critical")
    warnings  = sum(1 for c in non_ai if c.get("status") == "warning")

    try:
        from dateutil import parser as _dtp
        scan_date = _dtp.parse(scanned_at).strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        scan_date = scanned_at[:10] if scanned_at else "—"

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.add_page()

    # ── Header ──────────────────────────────────────────────────────────────
    pdf.set_fill_color(10, 10, 15)
    pdf.rect(0, 0, 210, 35, style="F")
    pdf.set_xy(20, 10)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(203, 255, 0)
    pdf.cell(0, 8, "SWARMHAWK — Security Report", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, f"Generated {scan_date}  |  CEE Cybersecurity Intelligence", ln=True)

    pdf.set_y(40)

    # ── Domain + score ──────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 20)
    score_col = (192, 57, 43) if risk_score >= 60 else (212, 133, 10) if risk_score >= 30 else (26, 122, 74)
    pdf.set_text_color(*score_col)
    pdf.cell(0, 10, f"Risk Score: {risk_score}/100", ln=True)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, domain, ln=True)
    pdf.ln(2)

    # ── Summary pills ───────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, f"Findings: {criticals} Critical  |  {warnings} Warnings  |  {len(non_ai)} Checks Total", ln=True)
    pdf.ln(4)

    # ── Horizontal rule ─────────────────────────────────────────────────────
    pdf.set_draw_color(200, 200, 200)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(4)

    # ── Checks table ────────────────────────────────────────────────────────
    CHECK_LABELS = {
        "ssl": "SSL/TLS", "headers": "Security Headers", "dns": "DNS",
        "http_redirect": "HTTPS Redirect", "breach": "Breach Exposure",
        "typosquat": "Typosquat", "response_time": "Response Time",
        "email_security": "Email Security", "whois": "WHOIS / RDAP",
        "urlhaus": "URLhaus Malware", "spamhaus": "Spamhaus DBL",
        "safebrowsing": "Safe Browsing", "virustotal": "VirusTotal",
        "cve": "CVE Scan", "sast": "SAST — Source Exposure",
        "sca": "SCA — Dependency CVEs", "dast": "DAST — App Testing",
        "iac": "IaC — Config Exposure", "ip_intel": "IP Intelligence",
    }

    for c in non_ai:
        status = c.get("status", "ok")
        label  = CHECK_LABELS.get(c.get("check", ""), c.get("check", "").replace("_", " ").upper())
        title  = c.get("title", "")
        detail = c.get("detail", "")

        color = STATUS_COLOR.get(status, (100, 100, 100))

        # Status badge
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 7)
        badge = STATUS_EMOJI.get(status, status.upper())
        pdf.cell(18, 6, badge, fill=True, align="C")
        pdf.set_x(pdf.get_x() + 2)

        # Check name
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(60, 6, label[:30])

        # Title
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 6, title[:120], ln=True)

        # Detail (for critical/warning only — skip ok to keep PDF short)
        if detail and status in ("critical", "warning"):
            pdf.set_x(22)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(100, 100, 100)
            # Limit detail to 3 lines
            short_detail = detail.replace("\n", " ")[:300]
            pdf.multi_cell(168, 5, short_detail, ln=True)

        pdf.ln(1)
        if pdf.get_y() > 270:   # page break guard
            pdf.add_page()

    # ── Footer ──────────────────────────────────────────────────────────────
    pdf.ln(6)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "SwarmHawk · CEE Cybersecurity Intelligence · www.swarmhawk.com", ln=True, align="C")
    pdf.cell(0, 5, "This report is confidential and intended for the named recipient only.", ln=True, align="C")

    return bytes(pdf.output())


class SendReportRequest(BaseModel):
    domain_id: str
    email: str


@app.post("/send-report")
def send_report_email(body: SendReportRequest, authorization: str = Header(None)):
    """Generate PDF report for a domain and email it to the requested address."""
    import re as _re
    import base64

    user = get_user_from_header(authorization)

    if not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', body.email):
        raise HTTPException(400, "Invalid email address")

    if not RESEND_API_KEY:
        raise HTTPException(503, "Email service not configured (RESEND_API_KEY missing)")

    db = get_db()

    # Fetch domain + latest scan (user must own the domain)
    domain_row = db.table("domains")\
        .select("*, scans(*), purchases(*)")\
        .eq("id", body.domain_id)\
        .eq("user_id", user["sub"])\
        .single()\
        .execute()

    if not domain_row.data:
        raise HTTPException(404, "Domain not found")

    d = domain_row.data
    scans = sorted(d.get("scans", []), key=lambda s: s["scanned_at"], reverse=True)
    if not scans:
        raise HTTPException(400, "No scan results yet — run a scan first")

    latest = scans[0]
    raw_checks = latest.get("checks", [])
    if isinstance(raw_checks, str):
        try:
            raw_checks = json.loads(raw_checks)
        except Exception:
            raw_checks = []
    checks = raw_checks if isinstance(raw_checks, list) else []

    risk_score = latest.get("risk_score") or 0
    scanned_at = latest.get("scanned_at", "")

    # Generate PDF
    try:
        pdf_bytes = _generate_pdf(d["domain"], risk_score, scanned_at, checks)
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {e}")

    pdf_b64 = base64.b64encode(pdf_bytes).decode()
    filename = f"swarmhawk-report-{d['domain']}-{scanned_at[:10]}.pdf"

    score_label = "HIGH RISK" if risk_score >= 60 else "MEDIUM RISK" if risk_score >= 30 else "LOW RISK"
    non_ai = [c for c in checks if c.get("check") != "ai_summary"]
    criticals = sum(1 for c in non_ai if c.get("status") == "critical")
    warnings  = sum(1 for c in non_ai if c.get("status") == "warning")

    email_html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#fff;padding:40px;border-radius:8px">
      <div style="margin-bottom:28px">
        <span style="font-family:monospace;font-size:18px;font-weight:700;color:#cbff00">●SWARMHAWK</span>
      </div>
      <h2 style="color:#fff;margin-bottom:4px">Security Report: {d['domain']}</h2>
      <p style="color:#888;font-size:13px;margin-bottom:24px">Scanned {scanned_at[:10]}</p>
      <div style="background:#111;border:1px solid #222;border-radius:8px;padding:20px;margin-bottom:24px;display:flex;gap:24px">
        <div style="text-align:center">
          <div style="font-size:32px;font-weight:700;color:{'#c0392b' if risk_score>=60 else '#d4850a' if risk_score>=30 else '#1a7a4a'}">{risk_score}</div>
          <div style="font-size:11px;color:#888;font-family:monospace">{score_label}</div>
        </div>
        <div style="border-left:1px solid #222;padding-left:24px">
          <div style="color:#c0392b;font-weight:700">{criticals} Critical</div>
          <div style="color:#d4850a;font-weight:700">{warnings} Warnings</div>
          <div style="color:#888;font-size:12px;margin-top:4px">{len(non_ai)} checks run</div>
        </div>
      </div>
      <p style="color:#aaa;font-size:13px;line-height:1.6">
        Your full security report for <strong style="color:#fff">{d['domain']}</strong> is attached as a PDF.
        It includes all check results, findings, and remediation recommendations.
      </p>
      <p style="color:#555;font-size:11px;margin-top:32px">
        SwarmHawk · CEE Cybersecurity Intelligence<br>
        This report is confidential and intended for the named recipient only.
      </p>
    </div>
    """

    try:
        import httpx as _httpx
        resp = _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from":    f"SwarmHawk Reports <{FROM_EMAIL}>",
                "to":      [body.email],
                "subject": f"Security Report: {d['domain']} — {score_label} ({risk_score}/100)",
                "html":    email_html,
                "attachments": [{"filename": filename, "content": pdf_b64}],
            },
            timeout=20,
        )
        if resp.status_code >= 400:
            raise HTTPException(502, f"Email send failed: {resp.text[:200]}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Email delivery failed: {e}")

    return {"sent": True, "to": body.email, "domain": d["domain"]}


@app.post("/checkout")
def create_checkout(body: CheckoutRequest, authorization: str = Header(None)):
    """
    Create a Stripe Checkout session.
    plan=one_time  → $10 one-time payment, unlocks full report permanently.
    plan=annual    → $50/year subscription, monthly auto-scans + reports.
    """
    user = get_user_from_header(authorization)
    db   = get_db()

    if body.plan not in ("one_time", "annual"):
        raise HTTPException(400, "plan must be 'one_time' or 'annual'")

    domain_row = db.table("domains")\
        .select("id, domain")\
        .eq("id", body.domain_id)\
        .eq("user_id", user["sub"])\
        .single()\
        .execute()

    if not domain_row.data:
        raise HTTPException(404, "Domain not found")

    meta = {
        "user_id":   str(user["sub"]),
        "domain_id": str(body.domain_id),
        "domain":    body.domain,
        "plan":      body.plan,
    }

    try:
        if body.plan == "one_time":
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="payment",
                line_items=[{
                    "price_data": {
                        "currency": "usd",
                        "unit_amount": 1000,        # $10.00
                        "product_data": {
                            "name": f"Security Report — {body.domain}",
                            "description": "Full 19-check security report with AI threat analysis. One-time purchase.",
                        },
                    },
                    "quantity": 1,
                }],
                success_url=f"{FRONTEND_URL}?payment=success&domain_id={body.domain_id}",
                cancel_url=f"{FRONTEND_URL}?payment=cancelled",
                metadata=meta,
                customer_email=user.get("email", ""),
            )
        else:  # annual subscription
            # Use a pre-created Price ID if set, otherwise create dynamically
            annual_price_id = os.getenv("STRIPE_ANNUAL_PRICE_ID", "")
            if annual_price_id:
                line_items = [{"price": annual_price_id, "quantity": 1}]
            else:
                # Dynamic price — works without pre-creating a product in dashboard
                line_items = [{
                    "price_data": {
                        "currency": "usd",
                        "unit_amount": 5000,        # $50.00
                        "recurring": {"interval": "year"},
                        "product_data": {
                            "name": "SwarmHawk Annual — Security Monitoring",
                            "description": f"Monthly automated scans + PDF reports for {body.domain}. Cancel anytime.",
                        },
                    },
                    "quantity": 1,
                }]

            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",
                line_items=line_items,
                success_url=f"{FRONTEND_URL}?payment=success&domain_id={body.domain_id}",
                cancel_url=f"{FRONTEND_URL}?payment=cancelled",
                metadata=meta,
                customer_email=user.get("email", ""),
                subscription_data={"metadata": meta},
            )

        return {"checkout_url": session.url, "session_id": session.id, "plan": body.plan}

    except stripe.error.StripeError as e:
        raise HTTPException(400, str(e))


def _record_purchase(db, user_id: str, domain_id: str, domain: str,
                     session_id: str, amount_cents: int, plan: str,
                     subscription_id: str | None = None):
    """Insert/upsert a purchase record and queue a rescan."""
    now = datetime.now(timezone.utc).isoformat()
    db.table("purchases").insert({
        "user_id":           user_id,
        "domain_id":         domain_id,
        "stripe_session_id": session_id,
        "stripe_sub_id":     subscription_id,
        "amount_usd":        amount_cents / 100,
        "plan":              plan,
        "paid_at":           now,
    }).execute()
    # Queue a full scan
    db.table("domains").update({"full_scan_enabled": True}).eq("id", domain_id).execute()
    print(f"[stripe] Purchase recorded: plan={plan} domain={domain} amount=${amount_cents/100:.2f}")


@app.post("/webhook")
async def stripe_webhook(request: Request):
    """
    Stripe webhook endpoint.
    Handles:
      checkout.session.completed    — both one-time and initial subscription payment
      invoice.payment_succeeded     — subscription renewal (trigger monthly rescan)
      customer.subscription.deleted — subscription cancelled, downgrade to free
    """
    payload    = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid webhook signature")

    db = get_db()

    # ── Initial payment (one-time or first subscription payment) ───────────────
    if event["type"] == "checkout.session.completed":
        session  = event["data"]["object"]
        meta     = session.get("metadata", {})
        user_id  = meta.get("user_id")
        domain_id= meta.get("domain_id")
        domain   = meta.get("domain", "")
        plan     = meta.get("plan", "one_time")

        if user_id and domain_id:
            sub_id = session.get("subscription")   # None for one-time
            _record_purchase(
                db, user_id, domain_id, domain,
                session["id"],
                session.get("amount_total") or (1000 if plan == "one_time" else 5000),
                plan,
                subscription_id=sub_id,
            )

    # ── Subscription renewal — queue a fresh scan each billing period ──────────
    elif event["type"] == "invoice.payment_succeeded":
        invoice = event["data"]["object"]
        sub_id  = invoice.get("subscription")
        # Only act on renewals (billing_reason = subscription_cycle), not first invoice
        if invoice.get("billing_reason") == "subscription_cycle" and sub_id:
            # Find the domain linked to this subscription
            purchases = db.table("purchases").select("domain_id, domain, user_id")\
                .eq("stripe_sub_id", sub_id).limit(1).execute()
            if purchases.data:
                p = purchases.data[0]
                db.table("domains").update({"full_scan_enabled": True}).eq("id", p["domain_id"]).execute()
                from threading import Thread
                Thread(target=run_scan_background, args=(p["domain_id"], p.get("domain", "")), daemon=True).start()
                print(f"[stripe] Subscription renewal scan queued for {p.get('domain')}")

    # ── Subscription cancelled ────────────────────────────────────────────────
    elif event["type"] == "customer.subscription.deleted":
        sub = event["data"]["object"]
        sub_id = sub.get("id")
        if sub_id:
            db.table("purchases").update({"cancelled_at": datetime.now(timezone.utc).isoformat()})\
                .eq("stripe_sub_id", sub_id).execute()
            print(f"[stripe] Subscription cancelled: {sub_id}")

    return {"received": True}


# ── Background scan ───────────────────────────────────────────────────────────

def _generate_ai_summary(domain: str, result: dict) -> str | None:
    """Call Anthropic to generate a 5-section Intelligence Report for the scan."""
    AKEY = os.getenv("ANTHROPIC_API_KEY", "")
    if not AKEY:
        return None
    checks = result.get("checks", [])
    critical = [c for c in checks if c.get("status") == "critical"]
    warnings = [c for c in checks if c.get("status") == "warning"]

    def fmt(items):
        return "\n".join(f"  - {c['check']}: {c['title']}" for c in items[:6])

    prompt = (
        f"Domain: {domain}\n"
        f"Risk score: {result['risk_score']}/100\n"
        f"Critical findings ({len(critical)}):\n{fmt(critical) or '  none'}\n"
        f"Warnings ({len(warnings)}):\n{fmt(warnings) or '  none'}\n\n"
        "Write a cybersecurity Intelligence Report with exactly these 5 sections. "
        "Use ONLY the following format — do not add any other text:\n\n"
        "1. Executive Summary\n\n"
        "<2-3 sentence overview of overall risk level and top concern>\n\n"
        "2. Critical Findings\n\n"
        "- <finding 1>\n- <finding 2>\n- <finding 3>\n\n"
        "3. Threat Scenarios\n\n"
        "- <realistic attack scenario 1>\n- <realistic attack scenario 2>\n- <realistic attack scenario 3>\n\n"
        "4. Recommendations\n\n"
        "- <specific action 1 with concrete detail>\n"
        "- <specific action 2 with concrete detail>\n"
        "- <specific action 3 with concrete detail>\n"
        "- <specific action 4 with concrete detail>\n"
        "- <specific action 5 with concrete detail>\n\n"
        "5. Intelligence Notes\n\n"
        "<1-2 sentences about hosting, CDN, architecture, or NIS2 compliance context>"
    )
    try:
        import requests as req
        r = req.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": AKEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 700,
                "system": "You are a cybersecurity analyst. Output only the report text in the exact format requested. No markdown, no backticks, no extra commentary.",
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=25,
        )
        if r.status_code == 200:
            data = r.json()
            return data["content"][0]["text"] if data.get("content") else None
    except Exception as e:
        print(f"AI summary generation failed for {domain}: {e}")
    return None


def run_scan_background(domain_id: str, domain: str):
    """Run scanner in background and save results to DB."""
    if not SCANNER_AVAILABLE:
        print(f"Scan skipped for {domain}: cee_scanner not installed on this server")
        return
    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)

        # Generate AI Intelligence Report (requires ANTHROPIC_API_KEY env var)
        ai_text = _generate_ai_summary(domain, result)
        if ai_text:
            result["checks"].append({
                "check": "ai_summary",
                "status": "ok",
                "title": "AI Intelligence Report",
                "detail": ai_text,
                "score_impact": 0,
            })

        db = get_db()
        # Pass list directly — NOT json.dumps — so supabase stores it as jsonb not a string
        db.table("scans").insert({
            "domain_id":  domain_id,
            "risk_score": result["risk_score"],
            "critical":   result["critical"],
            "warnings":   result["warnings"],
            "checks":     result["checks"],
            "scanned_at": result["scanned_at"],
        }).execute()
        print(f"Scan saved for {domain}: score={result['risk_score']}, checks={len(result['checks'])}, ai={'yes' if ai_text else 'no'}")
    except Exception as e:
        import traceback
        print(f"Background scan failed for {domain}: {e}\n{traceback.format_exc()}")
        # Save a minimal error record so the domain shows "scanned" not "pending" forever
        try:
            db = get_db()
            db.table("scans").insert({
                "domain_id":  domain_id,
                "risk_score": 0,
                "critical":   0,
                "warnings":   0,
                "checks":     [{"check": "error", "status": "error",
                                "title": "Scan failed", "detail": str(e)[:200],
                                "score_impact": 0}],
                "scanned_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
        except Exception:
            pass


# ── Passive prospect scan ─────────────────────────────────────────────────────

@app.get("/scan/passive")
async def passive_scan(domain: str, authorization: str = Header(None)):
    """
    Fast passive scan for Prospects tab — detects software versions and CVEs.
    Returns lightweight result without saving to DB. No payment required.
    """
    get_user_from_header(authorization)   # must be logged in

    import re, time
    import requests as req

    TIMEOUT = 8
    UA = {"User-Agent": "Mozilla/5.0 (compatible; SwarmHawk-Scout/1.0)"}

    HEADER_PATTERNS = [
        (r"nginx/(\d+\.\d+(?:\.\d+)?)",         "nginx"),
        (r"Apache/(\d+\.\d+(?:\.\d+)?)",         "Apache"),
        (r"Microsoft-IIS/(\d+\.\d+)",            "IIS"),
        (r"PHP/(\d+\.\d+(?:\.\d+)?)",            "PHP"),
        (r"WordPress/(\d+\.\d+(?:\.\d+)?)",      "WordPress"),
        (r"Drupal (\d+(?:\.\d+)*)",              "Drupal"),
    ]
    VERSION_PROBES = [
        ("/wp-json/",      r'"version":"(\d+\.\d+\.\d+)"',  "WordPress"),
        ("/wp-login.php",  r'ver=(\d+\.\d+\.\d+)',           "WordPress"),
        ("/",              r'content="WordPress (\d+\.\d+)', "WordPress"),
    ]

    software = []
    try:
        r = req.get(f"https://{domain}", timeout=TIMEOUT, headers=UA,
                    allow_redirects=True, verify=False)
        raw_headers = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        for pattern, product in HEADER_PATTERNS:
            m = re.search(pattern, raw_headers, re.IGNORECASE)
            if m:
                ver = m.group(1)
                if not any(s["product"] == product for s in software):
                    software.append({"product": product, "version": ver})
        body = r.text[:3000]
        for path, pattern, product in VERSION_PROBES:
            if path == "/":
                m = re.search(pattern, body, re.IGNORECASE)
                if m and not any(s["product"] == product for s in software):
                    software.append({"product": product, "version": m.group(1)})
    except Exception:
        pass

    for path, pattern, product in VERSION_PROBES:
        if path == "/": continue
        try:
            r2 = req.get(f"https://{domain}{path}", timeout=TIMEOUT, headers=UA, verify=False)
            if r2.status_code == 200:
                m = re.search(pattern, r2.text[:2000], re.IGNORECASE)
                if m and not any(s["product"] == product for s in software):
                    software.append({"product": product, "version": m.group(1)})
        except Exception:
            pass

    # NVD CVE lookup
    cve_hits = []
    NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_KEYWORDS = {
        "nginx": "nginx", "Apache": "apache http server",
        "PHP": "php", "WordPress": "wordpress",
        "Drupal": "drupal", "IIS": "microsoft iis",
    }
    for sw in software:
        if not sw["version"] or sw["version"] == "unknown":
            continue
        kw = NVD_KEYWORDS.get(sw["product"], sw["product"].lower())
        try:
            time.sleep(0.4)
            nresp = req.get(NVD, params={
                "keywordSearch": f"{kw} {sw['version']}",
                "cvssV3SeverityMin": "HIGH",
                "resultsPerPage": 5,
            }, timeout=10)
            if nresp.status_code == 200:
                vulns = nresp.json().get("vulnerabilities", [])
                best_score, best_id = 0, None
                for item in vulns:
                    cve = item.get("cve", {})
                    metrics = cve.get("metrics", {})
                    score = None
                    if "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    if score and score > best_score:
                        best_score, best_id = score, cve["id"]
                if best_id:
                    cve_hits.append({
                        "product":    sw["product"],
                        "version":    sw["version"],
                        "top_cve":    best_id,
                        "top_cvss":   best_score,
                        "cve_count":  len(vulns),
                    })
        except Exception:
            pass

    max_cvss = max((h["top_cvss"] for h in cve_hits), default=0)
    priority  = "CRITICAL" if max_cvss >= 9 else "HIGH" if max_cvss >= 7 else "MEDIUM" if max_cvss >= 4 else "LOW"

    return {
        "domain":    domain,
        "software":  software,
        "cve_hits":  cve_hits,
        "max_cvss":  max_cvss,
        "priority":  priority,
    }


# ── Intel endpoint ────────────────────────────────────────────────────────────

class IntelRequest(BaseModel):
    domains: str = ""
    date: str = ""
    prompt: str = ""
    max_tokens: int = 1000

@app.post("/intel")
async def intel(body: IntelRequest, authorization: str = Header(None)):
    """Generate AI threat briefing using server-side ANTHROPIC_API_KEY."""
    get_user_from_header(authorization)

    AKEY = os.getenv("ANTHROPIC_API_KEY", "")
    if not AKEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured on server")

    # Use custom prompt (outreach) or build briefing prompt (intelligence tab)
    if body.prompt:
        user_msg = body.prompt
        system   = "You are a professional cybersecurity copywriter. Be concise and direct."
        max_tok  = min(body.max_tokens, 600)
    else:
        user_msg = (
            f"Date: {body.date}. Monitored domains: {body.domains}.\n"
            "Generate a cybersecurity threat intelligence briefing as JSON:\n"
            '{"headline":"one sentence","briefing":"3 paragraphs","categories":['
            '{"title":"Active Threats","body":"2 sentences"},'
            '{"title":"CEE Regional","body":"2 sentences"},'
            '{"title":"Vulnerabilities","body":"2 sentences"},'
            '{"title":"Phishing","body":"2 sentences"},'
            '{"title":"Compliance","body":"2 sentences"},'
            '{"title":"Recommendations","body":"3 action items"}]}'
        )
        system  = "You are a cybersecurity analyst. Output valid JSON only, no markdown, no backticks."
        max_tok = 1000

    import httpx
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": AKEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": max_tok,
                "system": system,
                "messages": [{"role": "user", "content": user_msg}],
            },
        )

    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Anthropic API error: {r.text[:200]}")

    data = r.json()
    text = data["content"][0]["text"] if data.get("content") else ""
    return {"text": text, "briefing": text}


# ── Public scan (no auth, for landing page report) ───────────────────────────

class PublicScanRequest(BaseModel):
    domain: str

@app.post("/public-scan")
async def public_scan(body: PublicScanRequest):
    """Run a real scan for the landing page — no auth required, results not saved."""
    import re as _re
    domain = body.domain.lower().strip().replace("https://","").replace("http://","").split("/")[0]
    if not _re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
        raise HTTPException(400, "Invalid domain")

    if not SCANNER_AVAILABLE:
        raise HTTPException(503, "Scanner not available on this server — deploy cee_scanner/ into backend repo root")
    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)

        # Free tier: only show first 5 checks, lock the rest
        checks = result.get("checks", [])
        FREE_CHECKS = {"ssl", "headers", "dns", "sast", "sca", "dast", "iac"}
        free   = [c for c in checks if c.get("check") in FREE_CHECKS]
        locked = [c for c in checks if c.get("check") not in FREE_CHECKS and c.get("check") != "ai_summary"]

        # Mark locked checks
        for c in locked:
            c["status"]  = "locked"
            c["title"]   = "Upgrade to unlock"
            c["detail"]  = "Subscribe for €50/year to see this check"

        return {
            "domain":       domain,
            "risk_score":   result.get("risk_score", 0),
            "critical":     result.get("critical", 0),
            "warnings":     result.get("warnings", 0),
            "checks":       free + locked,
            "locked_count": len(locked),
            "scanned_at":   result.get("scanned_at", ""),
        }
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)[:200]}")
