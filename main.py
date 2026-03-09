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

    users     = db.table("users").select("id,created_at,auth_type").execute()
    domains   = db.table("domains").select("id,created_at").execute()
    purchases = db.table("purchases").select("amount_usd,paid_at").execute()
    scans     = db.table("scans").select("id,scanned_at").execute()

    now = datetime.now(timezone.utc)

    def within_days(rows, field, days):
        from datetime import timedelta
        cutoff = (now - timedelta(days=days)).isoformat()
        return sum(1 for r in rows if r.get(field, "") >= cutoff)

    revenue = sum(p.get("amount_usd", 0) or 0 for p in purchases.data)
    google_users = sum(1 for u in users.data if u.get("auth_type") != "email")
    email_users  = sum(1 for u in users.data if u.get("auth_type") == "email")

    return {
        "users": {
            "total":      len(users.data),
            "google":     google_users,
            "email":      email_users,
            "new_7d":     within_days(users.data, "created_at", 7),
            "new_30d":    within_days(users.data, "created_at", 30),
        },
        "domains": {
            "total":      len(domains.data),
            "new_7d":     within_days(domains.data, "created_at", 7),
            "new_30d":    within_days(domains.data, "created_at", 30),
        },
        "revenue": {
            "total_eur":  round(revenue, 2),
            "total_sales": len(purchases.data),
            "new_7d":     within_days(purchases.data, "paid_at", 7),
        },
        "scans": {
            "total":      len(scans.data),
            "last_7d":    within_days(scans.data, "scanned_at", 7),
        },
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
        result.append({
            "id":          d["id"],
            "domain":      d["domain"],
            "country":     d["country"],
            "added":       d["created_at"],
            "status":      "active" if latest_scan else "pending",
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

    # Free = threat intel checks only (urlhaus, safebrowsing, virustotal, spamhaus, breach, whois, email_security)
    # Paid = all checks including shodan, AI summary, all config checks
    FREE_CHECKS = {"urlhaus", "safebrowsing", "virustotal", "spamhaus", "breach",
                   "whois", "email_security", "ssl", "headers", "dns"}

    if is_paid:
        visible_checks = checks
    else:
        visible_checks = [c for c in checks if c.get("check") in FREE_CHECKS]

    return {
        "domain":      d["domain"],
        "risk_score":  latest["risk_score"],
        "scanned_at":  latest["scanned_at"],
        "paid":        is_paid,
        "checks":      visible_checks,
        "locked_count": len(checks) - len(visible_checks) if not is_paid else 0,
    }


@app.post("/checkout")
def create_checkout(body: CheckoutRequest, authorization: str = Header(None)):
    """Create Stripe checkout session for full report ($10)."""
    user = get_user_from_header(authorization)
    db = get_db()

    # Verify domain belongs to user
    domain = db.table("domains")\
        .select("id, domain")\
        .eq("id", body.domain_id)\
        .eq("user_id", user["sub"])\
        .single()\
        .execute()

    if not domain.data:
        raise HTTPException(status_code=404, detail="Domain not found")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 1000,  # $10.00
                    "product_data": {
                        "name": f"Full Security Report — {body.domain}",
                        "description": "15-check threat intelligence report + 1 year weekly monitoring",
                    },
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=f"{FRONTEND_URL}?payment=success&domain_id={body.domain_id}",
            cancel_url=f"{FRONTEND_URL}?payment=cancelled",
            metadata={
                "user_id":   str(user["sub"]),
                "domain_id": str(body.domain_id),
                "domain":    body.domain,
            },
            customer_email=user.get("email", ""),
        )
        return {"checkout_url": session.url, "session_id": session.id}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/webhook")
async def stripe_webhook(request: Request):
    """
    Stripe webhook — called automatically after successful payment.
    Marks domain as paid in the database.
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})

        user_id   = metadata.get("user_id")
        domain_id = metadata.get("domain_id")
        domain    = metadata.get("domain")

        if user_id and domain_id:
            db = get_db()
            # Record purchase
            db.table("purchases").insert({
                "user_id":          user_id,
                "domain_id":        domain_id,
                "stripe_session_id": session["id"],
                "amount_usd":       session.get("amount_total", 1000) / 100,
                "paid_at":          datetime.now(timezone.utc).isoformat(),
            }).execute()

            # Trigger full re-scan with all checks enabled
            db.table("domains").update({
                "full_scan_enabled": True
            }).eq("id", domain_id).execute()

    return {"received": True}


# ── Background scan ───────────────────────────────────────────────────────────

def run_scan_background(domain_id: str, domain: str):
    """Run scanner in background and save results to DB."""
    if not SCANNER_AVAILABLE:
        print(f"Scan skipped for {domain}: cee_scanner not installed on this server")
        return
    if not SCANNER_AVAILABLE:
        raise HTTPException(503, "Scanner not available on this server — deploy cee_scanner/ into backend repo root")
    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)
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
        print(f"Scan saved for {domain}: score={result['risk_score']}, checks={len(result['checks'])}")
    except Exception as e:
        import traceback
        print(f"Background scan failed for {domain}: {e}\n{traceback.format_exc()}")


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
        FREE_CHECKS = {"ssl", "headers", "dns", "typosquat", "open_ports"}
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
