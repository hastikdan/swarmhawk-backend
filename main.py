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

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from supabase import create_client, Client

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL        = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY", "")        # anon/service key
SUPABASE_SERVICE_KEY= os.getenv("SUPABASE_SERVICE_KEY", "")  # service_role key (bypasses RLS)
STRIPE_SECRET_KEY          = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET      = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID            = os.getenv("STRIPE_PRICE_ID", "")
STRIPE_MSP_PRICE_ID        = os.getenv("STRIPE_MSP_PRICE_ID", "")
STRIPE_API_STARTER_PRICE   = os.getenv("STRIPE_API_STARTER_PRICE", "")   # €19/mo — 500 calls
STRIPE_API_GROWTH_PRICE    = os.getenv("STRIPE_API_GROWTH_PRICE",  "")   # €49/mo — 2000 calls
STRIPE_API_PRO_PRICE       = os.getenv("STRIPE_API_PRO_PRICE",     "")   # €99/mo — 10000 calls

# Monthly call limits per API tier
API_PLAN_LIMITS = {
    "free":        10,
    "api_starter": 500,
    "api_growth":  2000,
    "api_pro":     10000,
}
FRONTEND_URL        = os.getenv("FRONTEND_URL", "https://hastikdan.github.io/cee-scanner")
ADMIN_EMAIL         = os.getenv("ADMIN_EMAIL", "hastikdan@gmail.com")  # super-admin
PORTKEY_API_KEY     = os.getenv("PORTKEY_API_KEY", "")                  # Portkey AI gateway key
PARANOIDLAB_API_KEY = os.getenv("PARANOIDLAB_API_KEY", "")              # paranoidlab.com leak intel
RESEND_API_KEY      = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL          = os.getenv("OUTREACH_FROM", "hello@swarmhawk.com")       # verified Resend domain
REPORT_FROM_EMAIL   = os.getenv("REPORT_FROM_EMAIL", "reports@swarmhawk.com") # user-facing reports
GOOGLE_CLIENT_ID    = os.getenv("GOOGLE_CLIENT_ID", "")
SITE_URL            = os.getenv("SITE_URL", "https://www.swarmhawk.com")
API_URL             = os.getenv("API_URL", "https://swarmhawk-backend.onrender.com")

stripe.api_key = STRIPE_SECRET_KEY

# ── Supabase clients ──────────────────────────────────────────────────────────

db: Client = None
admin_db: Client = None

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

def get_admin_db() -> Client:
    """Return a Supabase client using the service_role key to bypass RLS.
    Falls back to regular key if SUPABASE_SERVICE_KEY is not set."""
    global admin_db
    if admin_db is None:
        key = SUPABASE_SERVICE_KEY or SUPABASE_KEY
        if not SUPABASE_URL or not key:
            raise HTTPException(503, "Database not configured")
        try:
            admin_db = create_client(SUPABASE_URL, key)
        except Exception as e:
            raise HTTPException(503, f"Database connection failed: {str(e)[:200]}")
    return admin_db

# ── App ───────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager

SCANNER_AVAILABLE = False  # set True at startup if cee_scanner imports OK
_active_scans: dict = {}  # domain_id → {domain, started_at, user_id, status}

def _send_breach_monday():
    """Every Monday: email each user a digest of new threats found across their domains."""
    if not RESEND_API_KEY:
        return
    try:
        from datetime import timedelta
        import httpx as _hx
        _db = get_admin_db()
        now     = datetime.now(timezone.utc)
        week_ago = (now - timedelta(days=7)).isoformat()

        users = _db.table("users").select("id,email,name").execute()
        sent  = 0
        for u in (users.data or []):
            uid   = u["id"]
            email = u.get("email", "")
            name  = u.get("name") or "there"
            if not email:
                continue
            # Get all domains
            domains = _db.table("domains").select("id,domain").eq("user_id", uid).execute()
            if not domains.data:
                continue
            digest_rows = []
            for d in domains.data:
                # Latest scan vs scan from a week ago
                scans = _db.table("scans").select("risk_score,critical,warnings,checks,scanned_at")\
                    .eq("domain_id", d["id"]).order("scanned_at", desc=True).limit(2).execute()
                if not scans.data:
                    continue
                latest = scans.data[0]
                prev   = scans.data[1] if len(scans.data) > 1 else None
                score  = latest.get("risk_score") or 0
                prev_score = (prev.get("risk_score") or 0) if prev else score
                delta  = score - prev_score

                # Find new critical checks since last week
                raw = latest.get("checks", []) or []
                if isinstance(raw, str):
                    try: raw = json.loads(raw)
                    except: raw = []
                new_crits = [c["title"] for c in raw
                             if c.get("status") == "critical" and c.get("check") != "ai_summary"][:3]
                if new_crits or abs(delta) >= 10 or score >= 50:
                    digest_rows.append({
                        "domain": d["domain"], "score": score,
                        "delta": delta, "crits": new_crits,
                    })

            if not digest_rows:
                continue

            # Build email HTML
            rows_html = ""
            for r in sorted(digest_rows, key=lambda x: x["score"], reverse=True):
                sc = r["score"]
                c  = "#C0392B" if sc >= 70 else "#D4850A" if sc >= 40 else "#2ECC71"
                delta_str = (f'<span style="color:#C0392B">▲+{r["delta"]}</span>' if r["delta"] > 0
                             else f'<span style="color:#2ECC71">▼{r["delta"]}</span>' if r["delta"] < 0
                             else '<span style="color:#888">±0</span>')
                crits_html = ("".join(f"<li style='font-size:11px;color:#ccc'>{c}</li>"
                                       for c in r["crits"]) if r["crits"] else "")
                rows_html += f"""<tr>
  <td style="padding:10px 12px;font-family:monospace;color:#fff;border-bottom:1px solid #1a1a2e">{r['domain']}</td>
  <td style="padding:10px 12px;font-weight:700;color:{c};border-bottom:1px solid #1a1a2e">{sc} {delta_str}</td>
  <td style="padding:10px 12px;border-bottom:1px solid #1a1a2e"><ul style="margin:0;padding-left:14px">{crits_html}</ul></td>
</tr>"""

            try:
                _hx.post("https://api.resend.com/emails", headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                }, json={
                    "from":    f"SwarmHawk <{FROM_EMAIL}>",
                    "to":      [email],
                    "subject": f"⚡ Your weekly security digest — {len(digest_rows)} domain{'s' if len(digest_rows)>1 else ''} need attention",
                    "html":    f"""<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#0e0d12;color:#fff;max-width:600px;margin:0 auto;padding:24px">
<div style="border-left:3px solid #CBFF00;padding-left:16px;margin-bottom:20px">
  <strong style="font-family:monospace;font-size:16px;background:#CBFF00;color:#000;padding:4px 10px">SWARMHAWK</strong>
  <p style="color:#aaa;margin:6px 0 0;font-size:13px">Weekly Security Digest · {now.strftime('%d %b %Y')}</p>
</div>
<p style="color:#ccc">Hi {name},</p>
<p style="color:#ccc">Here's what SwarmHawk detected across your domains this week.</p>
<table style="width:100%;border-collapse:collapse;background:#13121A;border-radius:8px;overflow:hidden">
  <tr style="background:rgba(203,255,0,.08)">
    <th style="padding:8px 12px;text-align:left;font-family:monospace;font-size:10px;color:#CBFF00;letter-spacing:1px">DOMAIN</th>
    <th style="padding:8px 12px;text-align:left;font-family:monospace;font-size:10px;color:#CBFF00;letter-spacing:1px">RISK SCORE</th>
    <th style="padding:8px 12px;text-align:left;font-family:monospace;font-size:10px;color:#CBFF00;letter-spacing:1px">NEW THREATS</th>
  </tr>
  {rows_html}
</table>
<p style="margin-top:20px"><a href="{SITE_URL}" style="background:#CBFF00;color:#000;padding:10px 20px;text-decoration:none;font-family:monospace;font-weight:700;border-radius:6px;font-size:12px">View Full Reports →</a></p>
<hr style="border:none;border-top:1px solid #1a1a2e;margin:24px 0">
<p style="font-size:11px;color:#555">SwarmHawk Security Intelligence · swarmhawk.com · Unsubscribe by replying "unsubscribe"</p>
</body></html>""",
                }, timeout=15)
                sent += 1
            except Exception as e:
                print(f"[breach-monday] Failed to email {email}: {e}")

        print(f"[breach-monday] Sent weekly digest to {sent} users")
    except Exception as e:
        import traceback
        print(f"[breach-monday] Error: {e}\n{traceback.format_exc()}")


def _run_monthly_scans():
    """Daily job: scan any annual subscriber whose last scan is ≥30 days ago, then email PDF."""
    try:
        from datetime import timedelta
        _db = get_admin_db()
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(days=30)).isoformat()

        purchases = _db.table("purchases").select("domain_id, domain")\
            .eq("plan", "annual")\
            .is_("cancelled_at", "null")\
            .not_.is_("paid_at", "null")\
            .execute()

        for p in (purchases.data or []):
            domain_id = p.get("domain_id")
            domain    = p.get("domain", "")
            if not domain_id or not domain:
                continue
            last = _db.table("scans").select("scanned_at")\
                .eq("domain_id", domain_id)\
                .order("scanned_at", desc=True).limit(1).execute()
            last_at = last.data[0]["scanned_at"] if last.data else None
            if not last_at or last_at < cutoff:
                from threading import Thread
                Thread(target=run_scan_background, args=(domain_id, domain), daemon=True).start()
                print(f"[monthly-scheduler] Queued scan for {domain}")
    except Exception as e:
        import traceback
        print(f"[monthly-scheduler] Error: {e}\n{traceback.format_exc()}")


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
    # Start monthly scan scheduler for annual subscribers
    try:
        from apscheduler.schedulers.background import BackgroundScheduler as _BGScheduler
        _monthly_scheduler = _BGScheduler()
        _monthly_scheduler.add_job(_run_monthly_scans, "interval", hours=24, id="monthly_subscriber_scans")
        _monthly_scheduler.start()
        print("✓ Monthly scan scheduler started")
    except Exception as e:
        print(f"Monthly scheduler init failed: {e}")
    # Weekly "Breach Monday" digest — every Monday 08:00 Prague
    try:
        from apscheduler.schedulers.background import BackgroundScheduler as _BGS2
        _weekly_scheduler = _BGS2(timezone="Europe/Prague")
        _weekly_scheduler.add_job(_send_breach_monday, "cron", day_of_week="mon",
                                   hour=8, minute=0, id="breach_monday")
        _weekly_scheduler.start()
        print("✓ Breach Monday scheduler started")
    except Exception as e:
        print(f"Breach Monday scheduler init failed: {e}")
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


# ── TLD → ISO country resolver ────────────────────────────────────────────────

_TLD_COUNTRY: dict = {
    # Europe
    "cz":"CZ","pl":"PL","sk":"SK","hu":"HU","ro":"RO","at":"AT","de":"DE",
    "fr":"FR","gb":"GB","uk":"GB","it":"IT","es":"ES","nl":"NL","be":"BE",
    "se":"SE","no":"NO","dk":"DK","fi":"FI","ch":"CH","pt":"PT","gr":"GR",
    "ua":"UA","ru":"RU","tr":"TR","lt":"LT","lv":"LV","ee":"EE","hr":"HR",
    "si":"SI","bg":"BG","rs":"RS","ba":"BA","mk":"MK","md":"MD","al":"AL",
    "me":"ME","lu":"LU","ie":"IE","is":"IS","mt":"MT","cy":"CY","xk":"XK",
    # Americas
    "us":"US","ca":"CA","br":"BR","mx":"MX","ar":"AR","cl":"CL","co":"CO",
    # Asia-Pacific
    "au":"AU","nz":"NZ","jp":"JP","kr":"KR","cn":"CN","in":"IN","sg":"SG",
    "id":"ID","th":"TH","ph":"PH","my":"MY","vn":"VN","hk":"HK","tw":"TW",
    # Middle East / Africa
    "il":"IL","ae":"AE","sa":"SA","eg":"EG","ng":"NG","ke":"KE","za":"ZA",
    "pk":"PK","bd":"BD",
    # Generic gTLDs → US (global/English default)
    "com":"US","net":"US","org":"US","io":"US","co":"US","app":"US",
    "dev":"US","tech":"US","ai":"US","cloud":"US","online":"US","site":"US",
    "info":"US","biz":"US",
}

def tld_to_country(domain: str) -> str:
    """Infer ISO country code from the rightmost label of a domain."""
    tld = domain.lower().rstrip(".").rsplit(".", 1)[-1]
    return _TLD_COUNTRY.get(tld, "US")   # default US for unknown gTLDs

# ── Models ────────────────────────────────────────────────────────────────────

class AddDomainRequest(BaseModel):
    domain: str
    country: str = ""   # optional — derived from TLD if blank or "EU"

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

class DomainContactRequest(BaseModel):
    primary_contact: str

class DomainContactAddRequest(BaseModel):
    email: str

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

def send_welcome_and_confirm_email(to_email: str, name: str, token: str):
    """Send a single combined welcome + email-confirmation email from hello@swarmhawk.com."""
    if not RESEND_API_KEY:
        print(f"[auth] RESEND_API_KEY not set — skipping welcome email to {to_email}")
        return
    confirm_url = f"{API_URL}/auth/verify-email?token={token}"
    html = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#0e0d12;font-family:Arial,sans-serif">
<div style="max-width:580px;margin:0 auto;padding:48px 24px">

  <!-- Logo -->
  <div style="margin-bottom:32px">
    <span style="font-family:monospace;font-size:20px;font-weight:700;color:#cbff00;letter-spacing:1px">&#9679;SWARMHAWK</span>
  </div>

  <!-- Headline -->
  <h1 style="color:#f0eef8;font-size:22px;font-weight:700;margin:0 0 8px">Welcome to SwarmHawk, {name}</h1>
  <p style="color:#6b6880;font-size:14px;line-height:1.6;margin:0 0 32px">
    Your account is ready. Before you start, please confirm your email address.
  </p>

  <!-- Confirm button -->
  <div style="margin-bottom:40px">
    <a href="{confirm_url}"
       style="display:inline-block;background:#cbff00;color:#0e0d12;font-family:monospace;font-weight:700;font-size:13px;letter-spacing:1px;padding:14px 32px;border-radius:6px;text-decoration:none">
      CONFIRM MY EMAIL →
    </a>
    <p style="color:#555;font-size:11px;margin:12px 0 0;font-family:monospace">
      Link expires in 24 hours. If you didn't sign up, ignore this email.
    </p>
  </div>

  <!-- Divider -->
  <div style="border-top:1px solid rgba(255,255,255,.08);margin-bottom:32px"></div>

  <!-- What SwarmHawk does -->
  <p style="color:#6b6880;font-size:13px;margin:0 0 20px;line-height:1.6">
    SwarmHawk monitors your domains for security threats — continuously scanning for SSL issues, data breaches, exposed ports, malware listings, DNS misconfigurations, and more across 22 checks.
  </p>

  <!-- Steps -->
  <div style="background:#16151e;border-radius:8px;padding:20px;margin-bottom:32px">
    <div style="margin-bottom:16px">
      <span style="color:#cbff00;font-family:monospace;font-size:12px;font-weight:700">1. ADD YOUR DOMAIN</span><br>
      <span style="color:#6b6880;font-size:13px">Dashboard → Domains → Add Domain. 22 security checks run automatically.</span>
    </div>
    <div style="margin-bottom:16px">
      <span style="color:#cbff00;font-family:monospace;font-size:12px;font-weight:700">2. GET YOUR FREE REPORT</span><br>
      <span style="color:#6b6880;font-size:13px">SSL, DNS, breach detection, open ports, malware checks — all free.</span>
    </div>
    <div style="margin-bottom:16px">
      <span style="color:#cbff00;font-family:monospace;font-size:12px;font-weight:700">3. UNLOCK FULL INTELLIGENCE</span><br>
      <span style="color:#6b6880;font-size:13px">AI threat analysis + PDF reports for €50/year per domain.</span>
    </div>
    <div>
      <span style="color:#cbff00;font-family:monospace;font-size:12px;font-weight:700">4. NIS2 COMPLIANCE EVIDENCE</span><br>
      <span style="color:#6b6880;font-size:13px">Your reports document regular security monitoring as required under EU NIS2 law.</span>
    </div>
  </div>

  <!-- CTA -->
  <a href="{SITE_URL}"
     style="display:inline-block;background:rgba(203,255,0,.08);color:#cbff00;border:1px solid rgba(203,255,0,.25);font-family:monospace;font-weight:700;font-size:12px;letter-spacing:1px;padding:11px 24px;border-radius:6px;text-decoration:none">
    OPEN DASHBOARD →
  </a>

  <!-- Footer -->
  <p style="color:#3a3840;font-size:11px;margin-top:40px;font-family:monospace;line-height:1.8">
    SwarmHawk · European Cybersecurity Intelligence<br>
    hello@swarmhawk.com · swarmhawk.com<br>
    You received this because you created an account.
  </p>

</div>
</body>
</html>"""
    try:
        import httpx as _httpx
        r = _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from":    f"SwarmHawk <{FROM_EMAIL}>",
                "to":      [to_email],
                "subject": f"Confirm your SwarmHawk account, {name}",
                "html":    html,
            },
            timeout=10,
        )
        print(f"[auth] Welcome+confirm email sent to {to_email} (status {r.status_code})")
    except Exception as e:
        print(f"[auth] Failed to send welcome email to {to_email}: {e}")


def send_alert_email(to_email: str, domain: str, old_score: int, new_score: int,
                     new_threats: list[str]):
    """Send risk-change or new-threat alert email."""
    if not RESEND_API_KEY:
        return
    delta = new_score - old_score
    subject = f"⚠ Alert: {domain} risk {'increased' if delta > 0 else 'changed'} → {new_score}/100"
    threat_rows = "".join(
        f'<li style="color:#E74C3C;margin-bottom:4px">{t}</li>' for t in new_threats
    )
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#fff;padding:40px;border-radius:8px">
      <div style="margin-bottom:20px">
        <span style="font-family:monospace;font-size:18px;font-weight:700;color:#cbff00">●SWARMHAWK</span>
      </div>
      <h2 style="color:#E74C3C;margin-bottom:6px">Security Alert</h2>
      <h3 style="color:#fff;font-weight:400;margin-bottom:20px">{domain}</h3>
      <div style="background:#1a0a0a;border:1px solid rgba(192,57,43,.4);border-radius:8px;padding:20px;margin-bottom:20px">
        <div style="display:flex;gap:24px;align-items:center;margin-bottom:{'16px' if new_threats else '0'}">
          <div style="text-align:center">
            <div style="font-size:28px;font-weight:700;color:#888">{old_score}</div>
            <div style="font-size:10px;color:#555;font-family:monospace">PREVIOUS</div>
          </div>
          <div style="font-size:24px;color:#E74C3C">→</div>
          <div style="text-align:center">
            <div style="font-size:28px;font-weight:700;color:#E74C3C">{new_score}</div>
            <div style="font-size:10px;color:#555;font-family:monospace">NOW</div>
          </div>
        </div>
        {f'<ul style="margin:0;padding-left:18px">{threat_rows}</ul>' if new_threats else ""}
      </div>
      <p style="color:#888;font-size:13px;margin-bottom:20px">
        Log in to your dashboard to view the full report and remediation recommendations.
      </p>
      <a href="{SITE_URL}" style="display:inline-block;background:#cbff00;color:#000;font-family:monospace;font-weight:700;font-size:13px;padding:12px 24px;border-radius:5px;text-decoration:none">
        View Full Report →
      </a>
      <p style="color:#555;font-size:11px;margin-top:28px">SwarmHawk · European Cybersecurity Intelligence</p>
    </div>
    """
    try:
        import httpx as _httpx
        _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": f"SwarmHawk <{FROM_EMAIL}>", "to": [to_email],
                  "subject": subject, "html": html},
            timeout=10,
        )
        print(f"[alert] Alert sent to {to_email} for {domain}: {old_score}→{new_score}")
    except Exception as e:
        print(f"[alert] Failed to send alert: {e}")


def send_monthly_pdf_email(to_email: str, domain: str, risk_score: int,
                           scanned_at: str, checks: list):
    """Send monthly PDF report email to subscriber."""
    if not RESEND_API_KEY:
        return
    try:
        import base64
        pdf_bytes = _generate_pdf(domain, risk_score, scanned_at, checks)
        pdf_b64   = base64.b64encode(pdf_bytes).decode()
        filename  = f"swarmhawk-monthly-{domain}-{scanned_at[:10]}.pdf"
        score_col = "#C0392B" if risk_score >= 60 else "#D4850A" if risk_score >= 30 else "#1A7A4A"
        non_ai    = [c for c in checks if c.get("check") != "ai_summary"]
        crits     = sum(1 for c in non_ai if c.get("status") == "critical")
        warns     = sum(1 for c in non_ai if c.get("status") == "warning")
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#fff;padding:40px;border-radius:8px">
          <div style="margin-bottom:20px">
            <span style="font-family:monospace;font-size:18px;font-weight:700;color:#cbff00">●SWARMHAWK</span>
          </div>
          <h2 style="color:#fff;margin-bottom:4px">Monthly Security Report</h2>
          <p style="color:#888;font-size:13px;margin-bottom:20px">{domain} · {scanned_at[:10]}</p>
          <div style="background:#111;border-radius:8px;padding:20px;margin-bottom:20px;display:flex;gap:24px">
            <div style="text-align:center">
              <div style="font-size:32px;font-weight:700;color:{score_col}">{risk_score}</div>
              <div style="font-size:10px;color:#555;font-family:monospace">RISK SCORE</div>
            </div>
            <div style="border-left:1px solid #222;padding-left:20px">
              <div style="color:#C0392B;font-weight:700">{crits} Critical</div>
              <div style="color:#D4850A;font-weight:700">{warns} Warnings</div>
              <div style="color:#888;font-size:12px;margin-top:4px">{len(non_ai)} checks run</div>
            </div>
          </div>
          <p style="color:#aaa;font-size:13px;margin-bottom:20px">Your monthly security report is attached. It includes all check results and remediation recommendations.</p>
          <a href="{SITE_URL}" style="display:inline-block;background:#cbff00;color:#000;font-family:monospace;font-weight:700;font-size:13px;padding:12px 24px;border-radius:5px;text-decoration:none">Open Dashboard →</a>
          <p style="color:#555;font-size:11px;margin-top:28px">SwarmHawk · European Cybersecurity Intelligence · Cancel anytime at swarmhawk.com</p>
        </div>
        """
        import httpx as _httpx
        _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": f"SwarmHawk Reports <{REPORT_FROM_EMAIL}>", "to": [to_email],
                  "subject": f"Monthly Security Report: {domain} — {scanned_at[:10]}",
                  "html": html,
                  "attachments": [{"filename": filename, "content": pdf_b64}]},
            timeout=20,
        )
        print(f"[monthly] PDF report sent to {to_email} for {domain}")
    except Exception as e:
        print(f"[monthly] Failed to send monthly PDF: {e}")


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
        send_welcome_and_confirm_email, body.email.lower(), body.username.strip(), verification_token
    )

    # Add first domain if provided
    first_domain = None
    if body.domain:
        domain = body.domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        if _re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
            dom_result = db.table("domains").insert({
                "user_id":    user["id"],
                "domain":     domain,
                "country":    tld_to_country(domain),
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


class TestWelcomeEmailRequest(BaseModel):
    to: str
    name: str = "Test User"

@app.post("/admin/test-welcome-email")
def test_welcome_email(body: TestWelcomeEmailRequest, authorization: str = Header(None)):
    """Send a test welcome+confirmation email to verify the template and Resend config."""
    import re as _re
    require_admin(authorization)
    if not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', body.to):
        raise HTTPException(400, "Invalid email address")
    if not RESEND_API_KEY:
        raise HTTPException(503, "RESEND_API_KEY not set — configure it in Render environment variables")
    fake_token = "test_" + secrets.token_urlsafe(16)
    try:
        send_welcome_and_confirm_email(body.to, body.name, fake_token)
        return {
            "sent_to":    body.to,
            "from":       FROM_EMAIL,
            "confirm_url": f"{API_URL}/auth/verify-email?token={fake_token}",
            "note":       "Confirmation link is a test token and will not verify any account",
        }
    except Exception as e:
        raise HTTPException(500, f"Send failed: {e}")


class GoogleAuthRequest(BaseModel):
    credential: str  # Google ID token (JWT)

@app.post("/auth/google")
async def google_auth(body: GoogleAuthRequest, background_tasks: BackgroundTasks):
    """Verify Google ID token and return a session JWT. Creates user on first sign-in."""
    import requests as _req
    try:
        r = _req.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": body.credential},
            timeout=8,
        )
        if r.status_code != 200:
            raise HTTPException(401, "Invalid Google token")
        info = r.json()
        if info.get("error"):
            raise HTTPException(401, info.get("error_description", "Google token error"))
        if GOOGLE_CLIENT_ID and info.get("aud") != GOOGLE_CLIENT_ID:
            raise HTTPException(401, "Token audience mismatch")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(401, f"Google verification failed: {e}")

    email  = info.get("email", "").lower()
    name   = info.get("name") or info.get("given_name") or email.split("@")[0]
    avatar = info.get("picture", "")
    g_id   = info.get("sub", "")

    if not email:
        raise HTTPException(400, "Google account has no email")

    db = get_db()
    existing = db.table("users").select("*").eq("email", email).execute()
    if existing.data:
        user = existing.data[0]
        db.table("users").update({
            "last_login": datetime.now(timezone.utc).isoformat(),
            "avatar":     avatar,
        }).eq("id", user["id"]).execute()
    else:
        import uuid
        user_id = str(uuid.uuid4())
        db.table("users").insert({
            "id":         user_id,
            "email":      email,
            "name":       name,
            "avatar":     avatar,
            "google_id":  g_id,
            "auth_type":  "google",
            "email_verified": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": datetime.now(timezone.utc).isoformat(),
        }).execute()
        user = {"id": user_id, "email": email, "name": name, "avatar": avatar}
        background_tasks.add_task(send_welcome_email, email, name)

    token = make_session(user["id"])
    return {
        "session_token": token,
        "user": {
            "id":       user["id"],
            "email":    email,
            "name":     name,
            "avatar":   avatar,
            "is_admin": is_admin(user["id"]),
        },
    }


@app.get("/admin/users")
def admin_users(
    page: int = 1,
    per_page: int = 50,
    authorization: str = Header(None),
):
    """Full user list with domain counts and last login. Admin only."""
    require_admin(authorization)
    db = get_admin_db()

    # 1. Fetch paginated users
    offset = (page - 1) * per_page
    users_res = db.table("users").select("id,email,name,auth_type,created_at,last_login") \
        .order("created_at", desc=True).range(offset, offset + per_page - 1).execute()
    total_res = db.table("users").select("id", count="exact").execute()

    user_ids = [u["id"] for u in (users_res.data or [])]
    if not user_ids:
        return {"users": [], "total": total_res.count or 0, "page": page, "per_page": per_page}

    # 2. Fetch domain counts for these users in one query
    domains_res = db.table("domains").select("user_id").in_("user_id", user_ids).execute()
    domain_counts: dict = {}
    for d in (domains_res.data or []):
        uid = d["user_id"]
        domain_counts[uid] = domain_counts.get(uid, 0) + 1

    # 3. Fetch purchase counts in one query
    paid_res = db.table("purchases").select("user_id").in_("user_id", user_ids).execute()
    paid_counts: dict = {}
    for p in (paid_res.data or []):
        uid = p["user_id"]
        paid_counts[uid] = paid_counts.get(uid, 0) + 1

    rows = []
    for u in (users_res.data or []):
        uid = u["id"]
        rows.append({
            "id":           uid,
            "email":        u.get("email", ""),
            "name":         u.get("name", ""),
            "auth_type":    u.get("auth_type", "google"),
            "domain_count": domain_counts.get(uid, 0),
            "paid_domains": paid_counts.get(uid, 0),
            "created_at":   u.get("created_at", ""),
            "last_login":   u.get("last_login", ""),
        })

    return {"users": rows, "total": total_res.count or 0, "page": page, "per_page": per_page}


@app.get("/admin/domains")
def admin_domains(
    page: int = 1,
    per_page: int = 50,
    authorization: str = Header(None),
):
    """All domains across all users with scan status. Admin only."""
    require_admin(authorization)
    db = get_admin_db()

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
    db = get_admin_db()

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

    # API key usage stats
    try:
        api_key_rows = db.table("api_keys").select("user_id,calls_this_month,limit_per_month,active,created_at").execute()
        api_keys_data = api_key_rows.data or []
    except Exception:
        api_keys_data = []
    active_keys    = [k for k in api_keys_data if k.get("active", True)]
    total_api_calls = sum(k.get("calls_this_month") or 0 for k in api_keys_data)
    new_keys_7d    = within_days(api_keys_data, "created_at", 7)
    new_keys_30d   = within_days(api_keys_data, "created_at", 30)
    # Top 5 API users by calls this month
    top_api = sorted(
        [{"user_id": k.get("user_id","?"), "key": (k.get("key") or "")[:12]+"…",
          "calls": k.get("calls_this_month") or 0, "limit": k.get("limit_per_month") or 10}
         for k in api_keys_data if k.get("calls_this_month")],
        key=lambda x: x["calls"], reverse=True
    )[:5]

    return {
        "users": {
            "total":      len(users.data),
            "google":     len(users.data) - email_users,
            "email":      email_users,
            "new_7d":     within_days(users.data, "created_at", 7),
            "new_30d":    within_days(users.data, "created_at", 30),
        },
        "api_keys": {
            "total":           len(api_keys_data),
            "active":          len(active_keys),
            "calls_this_month": total_api_calls,
            "new_7d":          new_keys_7d,
            "new_30d":         new_keys_30d,
            "top_users":       top_api,
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


@app.get("/admin/api-keys")
def admin_list_api_keys(authorization: str = Header(None)):
    """List all API keys with owner info. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    rows = db.table("api_keys").select("key,user_id,calls_this_month,limit_per_month,active,created_at").execute()
    keys = rows.data or []
    user_ids = list({k["user_id"] for k in keys if k.get("user_id")})
    user_map = {}
    if user_ids:
        users = db.table("users").select("id,email,name").in_("id", user_ids).execute()
        for u in (users.data or []):
            user_map[u["id"]] = {"email": u.get("email", ""), "name": u.get("name", "")}
    for k in keys:
        u = user_map.get(k.get("user_id", ""), {})
        k["user_email"] = u.get("email", "—")
        k["user_name"]  = u.get("name",  "—")
    keys.sort(key=lambda k: k.get("calls_this_month") or 0, reverse=True)
    return {"keys": keys}


class AdminKeyLimitBody(BaseModel):
    limit: int

@app.patch("/admin/api-keys/{key}/limit")
def admin_set_key_limit(key: str, body: AdminKeyLimitBody, authorization: str = Header(None)):
    """Set monthly call limit for any API key. Admin only."""
    require_admin(authorization)
    if body.limit < 1:
        raise HTTPException(400, "Limit must be at least 1")
    db = get_admin_db()
    db.table("api_keys").update({"limit_per_month": body.limit}).eq("key", key).execute()
    return {"key": key, "limit": body.limit}


@app.post("/admin/api-keys/{key}/reset-calls")
def admin_reset_key_calls(key: str, authorization: str = Header(None)):
    """Reset monthly call counter to 0. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    db.table("api_keys").update({"calls_this_month": 0}).eq("key", key).execute()
    return {"reset": key}


@app.patch("/admin/api-keys/{key}/toggle")
def admin_toggle_key(key: str, authorization: str = Header(None)):
    """Enable or disable an API key. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    existing = db.table("api_keys").select("active").eq("key", key).execute()
    if not existing.data:
        raise HTTPException(404, "Key not found")
    new_state = not existing.data[0].get("active", True)
    db.table("api_keys").update({"active": new_state}).eq("key", key).execute()
    return {"key": key, "active": new_state}


@app.delete("/admin/api-keys/{key}")
def admin_revoke_key(key: str, authorization: str = Header(None)):
    """Hard-delete any API key. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    db.table("api_keys").delete().eq("key", key).execute()
    return {"revoked": key}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, authorization: str = Header(None)):
    """Delete a user and all their data. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    db.table("users").delete().eq("id", user_id).execute()
    return {"deleted": user_id}


@app.post("/admin/users/{user_id}/rescan-all")
def admin_rescan_user(user_id: str, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Force re-scan all domains for a user. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    doms = db.table("domains").select("id,domain").eq("user_id", user_id).execute()
    for d in (doms.data or []):
        background_tasks.add_task(run_scan_background, d["id"], d["domain"])
    return {"queued": len(doms.data or [])}


@app.get("/admin/scans/active")
def admin_active_scans(authorization: str = Header(None)):
    """Return currently running domain scans + marketing scan progress."""
    user = get_user_from_header(authorization)
    if not is_admin(user["sub"]):
        raise HTTPException(403, "Admin only")
    from outreach import _scan_progress
    return {
        "domain_scans": [{"domain_id": k, **v} for k, v in _active_scans.items()],
        "marketing_scan": _scan_progress,
    }

@app.get("/admin/scans/history")
def admin_scan_history(authorization: str = Header(None)):
    """Return recent domain scans and marketing scan log."""
    user = get_user_from_header(authorization)
    if not is_admin(user["sub"]):
        raise HTTPException(403, "Admin only")
    db = get_db()
    try:
        scans = db.table("scans")\
            .select("id,domain_id,risk_score,critical,warnings,scanned_at,domains(domain)")\
            .order("scanned_at", desc=True).limit(100).execute()
    except Exception:
        scans_data = []
    else:
        scans_data = scans.data or []
    try:
        logs = db.table("outreach_log").select("*").order("ran_at", desc=True).limit(20).execute()
    except Exception:
        logs_data = []
    else:
        logs_data = logs.data or []
    return {"domain_scans": scans_data, "marketing_scans": logs_data}

@app.get("/admin/portkey/usage")
def admin_portkey_usage(authorization: str = Header(None)):
    """Fetch AI cost/usage data from Portkey analytics API."""
    user = get_user_from_header(authorization)
    if not is_admin(user["sub"]):
        raise HTTPException(403, "Admin only")
    if not PORTKEY_API_KEY:
        return {"error": "Portkey not configured", "total_requests": 0, "total_cost": 0}
    try:
        import httpx as _httpx
        resp = _httpx.get(
            "https://api.portkey.ai/v1/analytics",
            headers={"x-portkey-api-key": PORTKEY_API_KEY, "Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        # Try logs endpoint as fallback
        resp2 = _httpx.get(
            "https://api.portkey.ai/v1/logs?limit=100&order=desc",
            headers={"x-portkey-api-key": PORTKEY_API_KEY},
            timeout=10,
        )
        if resp2.status_code == 200:
            data = resp2.json()
            logs = data.get("data", data.get("logs", []))
            total_cost = sum(float(l.get("cost", 0) or 0) for l in logs)
            total_tokens = sum(int(l.get("usage", {}).get("total_tokens", 0) or 0) for l in logs)
            return {
                "total_requests": len(logs),
                "total_tokens": total_tokens,
                "total_cost": round(total_cost, 4),
                "logs": logs[:20],  # last 20 calls
            }
        return {"error": f"Portkey API returned {resp.status_code}", "total_requests": 0, "total_cost": 0}
    except Exception as e:
        return {"error": str(e), "total_requests": 0, "total_cost": 0}


@app.get("/admin/llm-stats")
async def admin_llm_stats(
    authorization: str = Header(None),
    period: str = Query("month"),  # "day" | "month" | "year"
):
    """Fetch LLM usage, cost, per-domain, and time-series breakdown from Portkey."""
    require_admin(authorization)

    if not PORTKEY_API_KEY:
        return {
            "configured": False,
            "message": "PORTKEY_API_KEY not set — add it to Render env vars to enable LLM observability",
        }

    pk_headers = {
        "x-portkey-api-key": PORTKEY_API_KEY,
        "Content-Type": "application/json",
    }
    now = datetime.now(timezone.utc)

    # Compute period start based on requested granularity
    if period == "day":
        period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        period_label = "today"
        ts_fmt = "%H:00"          # group by hour
        ts_key = lambda ts: ts[:13]  # "YYYY-MM-DDTHH"
    elif period == "year":
        period_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        period_label = "this year"
        ts_fmt = "%b %Y"          # group by month "Jan 2025"
        ts_key = lambda ts: ts[:7]   # "YYYY-MM"
    else:  # month (default)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        period_label = "this month"
        ts_fmt = "%d %b"          # group by day "01 Mar"
        ts_key = lambda ts: ts[:10]  # "YYYY-MM-DD"

    period_start_iso = period_start.isoformat()

    try:
        import httpx
        async with httpx.AsyncClient(timeout=30) as client:
            # 1. Aggregate analytics for the period
            analytics_r = await client.get(
                "https://api.portkey.ai/v1/analytics",
                headers=pk_headers,
                params={"filters[time_of_generation][gt]": period_start_iso},
            )
            analytics = analytics_r.json() if analytics_r.status_code == 200 else {}

            # 2. Fetch logs for the period (up to 500 for richer breakdowns)
            logs_r = await client.get(
                "https://api.portkey.ai/v1/logs",
                headers=pk_headers,
                params={
                    "page_size": 500,
                    "page": 0,
                    "filters[time_of_generation][gt]": period_start_iso,
                },
            )
            logs_data = logs_r.json() if logs_r.status_code == 200 else {}

    except Exception as e:
        raise HTTPException(502, f"Portkey API error: {e}")

    # Parse analytics totals (Portkey shape varies by version)
    totals = analytics.get("total", analytics)
    total_cost        = float(totals.get("cost", totals.get("total_cost", 0)) or 0)
    total_tokens      = int(totals.get("tokens", totals.get("total_tokens", 0)) or 0)
    total_requests    = int(totals.get("requests", totals.get("total_requests", 0)) or 0)
    prompt_tokens     = int(totals.get("prompt_tokens", 0) or 0)
    completion_tokens = int(totals.get("completion_tokens", 0) or 0)

    # Parse logs for per-domain, per-user, per-type, and time-series breakdowns
    logs       = logs_data.get("data", logs_data.get("logs", []))
    user_map   = {}   # user_id  -> {cost, tokens, requests}
    type_map   = {}   # report_type -> {cost, tokens, requests}
    domain_map = {}   # domain   -> {cost, tokens, requests}
    time_map   = {}   # date_key -> {cost, tokens, requests}

    import json as _j
    for log in logs:
        meta = log.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = _j.loads(meta)
            except Exception:
                meta = {}

        uid    = meta.get("_user", "anonymous")
        rtype  = meta.get("report_type", "unknown")
        domain = meta.get("domain", "")
        cost   = float(log.get("cost", 0) or 0)
        toks   = int(log.get("total_tokens", 0) or 0)

        # ── time key from log timestamp ──────────────────────────────────────
        ts_raw = log.get("created_at") or log.get("time_of_generation") or ""
        try:
            dk = ts_key(ts_raw) if ts_raw else ""
        except Exception:
            dk = ""

        def _add(m, key, label_key, label_val):
            if key not in m:
                m[key] = {label_key: label_val, "cost": 0.0, "tokens": 0, "requests": 0}
            m[key]["cost"]     += cost
            m[key]["tokens"]   += toks
            m[key]["requests"] += 1

        _add(user_map,   uid,    "user_id",     uid)
        _add(type_map,   rtype,  "report_type", rtype)
        if domain:
            _add(domain_map, domain, "domain",  domain)
        if dk:
            _add(time_map,   dk,     "date_key", dk)

    # Enrich user breakdown with emails
    db = get_admin_db()
    user_ids  = [u for u in user_map if u != "anonymous"]
    email_map = {}
    if user_ids:
        try:
            rows = db.table("users").select("id,email,name").in_("id", user_ids).execute()
            for row in (rows.data or []):
                email_map[row["id"]] = row.get("email", "")
        except Exception:
            pass

    user_breakdown = sorted(user_map.values(), key=lambda x: x["cost"], reverse=True)
    for u in user_breakdown:
        u["email"] = email_map.get(u["user_id"], u["user_id"][:8] + "…")
        u["cost"]  = round(u["cost"], 6)

    domain_breakdown = sorted(domain_map.values(), key=lambda x: x["cost"], reverse=True)
    for d in domain_breakdown:
        d["cost"] = round(d["cost"], 6)

    type_breakdown = sorted(type_map.values(), key=lambda x: x["requests"], reverse=True)

    # Build sorted time series
    time_series = sorted(
        [{"date": k, "cost": round(v["cost"], 6), "tokens": v["tokens"], "requests": v["requests"]}
         for k, v in time_map.items()],
        key=lambda x: x["date"],
    )

    return {
        "configured":    True,
        "period":        period_label,
        "period_key":    period,
        "totals": {
            "cost":              round(total_cost, 6),
            "tokens":            total_tokens,
            "prompt_tokens":     prompt_tokens,
            "completion_tokens": completion_tokens,
            "requests":          total_requests,
            "avg_cost_per_req":  round(total_cost / max(total_requests, 1), 6),
        },
        "by_domain":      domain_breakdown[:100],
        "by_user":        user_breakdown[:50],
        "by_report_type": type_breakdown,
        "time_series":    time_series,
    }


# ── PDF Report Email Template ─────────────────────────────────────────────────
# Variables available in both subject and body:
#   {domain}       – the scanned domain name
#   {risk_score}   – numeric risk score 0-100
#   {score_label}  – HIGH RISK / MEDIUM RISK / LOW RISK
#   {criticals}    – number of critical findings
#   {warnings}     – number of warning findings
#   {checks_count} – total checks run
#   {scanned_at}   – date of scan (YYYY-MM-DD)

_REPORT_EMAIL_DEFAULTS = {
    "subject": "Security Report: {domain} — {score_label} ({risk_score}/100)",
    "body":    (
        "Your full security report for <strong>{domain}</strong> is attached as a PDF. "
        "It includes {checks_count} security checks, {criticals} critical findings, and remediation recommendations.<br><br>"
        "Sign up free at <a href=\"https://www.swarmhawk.com\" style=\"color:#cbff00\">swarmhawk.com</a> "
        "to monitor this domain continuously, receive alerts on new threats, and access your full interactive dashboard."
    ),
    "footer":  "SwarmHawk · European Cybersecurity Intelligence · www.swarmhawk.com<br>This report is confidential and intended for the named recipient only.",
}

_report_email_cache: dict | None = None


def _get_report_email_template() -> dict:
    global _report_email_cache
    if _report_email_cache is not None:
        return _report_email_cache
    try:
        db = get_db()
        rows = db.table("admin_settings").select("key,value").in_("key", ["report_subject", "report_body", "report_footer"]).execute()
        tpl = dict(_REPORT_EMAIL_DEFAULTS)
        for row in (rows.data or []):
            k = row["key"].replace("report_", "")
            tpl[k] = row["value"]
        _report_email_cache = tpl
        return tpl
    except Exception:
        return dict(_REPORT_EMAIL_DEFAULTS)


class ReportEmailTemplate(BaseModel):
    subject: str
    body:    str
    footer:  str = ""


@app.get("/admin/report-email-template")
def get_report_email_template(authorization: str = Header(None)):
    require_admin(authorization)
    return {"template": _get_report_email_template(), "defaults": _REPORT_EMAIL_DEFAULTS}


@app.put("/admin/report-email-template")
def save_report_email_template(body: ReportEmailTemplate, authorization: str = Header(None)):
    global _report_email_cache
    require_admin(authorization)
    db = get_db()
    for key, val in [("report_subject", body.subject), ("report_body", body.body), ("report_footer", body.footer)]:
        db.table("admin_settings").upsert({"key": key, "value": val, "updated_at": datetime.now(timezone.utc).isoformat()}, on_conflict="key").execute()
    _report_email_cache = {"subject": body.subject, "body": body.body, "footer": body.footer}
    return {"saved": True}


@app.delete("/admin/report-email-template")
def reset_report_email_template(authorization: str = Header(None)):
    global _report_email_cache
    require_admin(authorization)
    db = get_db()
    db.table("admin_settings").delete().in_("key", ["report_subject", "report_body", "report_footer"]).execute()
    _report_email_cache = None
    return {"reset": True, "template": _REPORT_EMAIL_DEFAULTS}


class ReportEmailTestRequest(BaseModel):
    to:      str
    subject: str = ""
    body:    str = ""
    footer:  str = ""


@app.post("/admin/report-email-template/test")
def send_test_report_email(body: ReportEmailTestRequest, authorization: str = Header(None)):
    """Send a preview of the report email template to the admin's own inbox."""
    import re as _re
    import base64
    require_admin(authorization)
    if not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', body.to):
        raise HTTPException(400, "Invalid recipient email")
    if not RESEND_API_KEY:
        raise HTTPException(503, "Email service not configured (RESEND_API_KEY missing)")

    # Build a preview using placeholder values
    tpl_vars = dict(
        domain="example.com", risk_score=72, score_label="HIGH RISK",
        criticals=3, warnings=5, checks_count=22, scanned_at="2026-03-15",
    )
    subject_tpl = body.subject or _REPORT_EMAIL_DEFAULTS["subject"]
    body_tpl    = body.body    or _REPORT_EMAIL_DEFAULTS["body"]
    footer_tpl  = body.footer  or _REPORT_EMAIL_DEFAULTS["footer"]
    try:
        subject_str = subject_tpl.format(**tpl_vars)
    except (KeyError, ValueError):
        subject_str = subject_tpl
    try:
        body_str = body_tpl.format(**tpl_vars)
    except (KeyError, ValueError):
        body_str = body_tpl
    try:
        footer_str = footer_tpl.format(**tpl_vars)
    except (KeyError, ValueError):
        footer_str = footer_tpl

    score_color = "#c0392b"
    email_html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#fff;border-radius:8px;overflow:hidden">
      <div style="background:#0e0d12;padding:28px 36px;border-bottom:1px solid #1a1a1a">
        <span style="font-family:monospace;font-size:18px;font-weight:700;color:#cbff00">&#9679;SWARMHAWK</span>
        <span style="font-family:monospace;font-size:11px;color:#444;margin-left:12px">Preview — Template Test</span>
      </div>
      <div style="padding:32px 36px">
        <div style="background:#1a0a0a;border:1px solid #3a1a1a;border-radius:6px;padding:10px 14px;margin-bottom:20px;font-family:monospace;font-size:11px;color:#c0392b">
          ⚠ This is a <strong>template preview</strong> with placeholder data — not a real scan result.
        </div>
        <h2 style="color:#fff;margin:0 0 4px 0;font-size:20px">Security Report: example.com</h2>
        <p style="color:#666;font-size:12px;margin:0 0 24px 0;font-family:monospace">Scanned 2026-03-15</p>
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:8px;padding:20px 24px;margin-bottom:24px;display:flex;align-items:center;gap:28px">
          <div style="text-align:center;min-width:60px">
            <div style="font-size:36px;font-weight:800;color:{score_color};line-height:1">72</div>
            <div style="font-size:10px;color:#888;font-family:monospace;margin-top:4px">HIGH RISK</div>
          </div>
          <div style="border-left:1px solid #2a2a2a;padding-left:24px;flex:1">
            <div style="color:#c0392b;font-weight:700;font-size:14px">3 Critical</div>
            <div style="color:#d4850a;font-weight:700;font-size:14px">5 Warnings</div>
            <div style="color:#555;font-size:12px;margin-top:6px">22 checks run</div>
          </div>
        </div>
        <div style="background:#111;border:1px solid #1e3a1e;border-radius:6px;padding:14px 18px;margin-bottom:20px;display:flex;align-items:center;gap:12px">
          <span style="font-size:22px">&#128196;</span>
          <div>
            <div style="color:#cbff00;font-family:monospace;font-size:11px;font-weight:700;letter-spacing:1px">PDF REPORT ATTACHED</div>
            <div style="color:#888;font-size:12px;margin-top:2px">swarmhawk-report-example.com-2026-03-15.pdf — full findings &amp; remediation</div>
          </div>
        </div>
        <p style="color:#aaa;font-size:13px;line-height:1.7;margin-bottom:28px">{body_str}</p>
        <div style="margin-bottom:28px">
          <a href="https://www.swarmhawk.com" style="display:inline-block;background:#cbff00;color:#000;font-family:monospace;font-weight:700;font-size:13px;padding:13px 26px;border-radius:6px;text-decoration:none;margin-right:12px;margin-bottom:10px">Get Free Account &#8594;</a>
        </div>
      </div>
      <div style="background:#0e0d12;border-top:1px solid #1a1a1a;padding:18px 36px">
        <p style="color:#444;font-size:11px;margin:0;line-height:1.7">{footer_str}</p>
      </div>
    </div>
    """

    try:
        import httpx as _httpx
        resp = _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from":    f"SwarmHawk Reports <{REPORT_FROM_EMAIL}>",
                "to":      [body.to],
                "subject": f"[TEST PREVIEW] {subject_str}",
                "html":    email_html,
            },
            timeout=20,
        )
        if resp.status_code >= 400:
            raise HTTPException(502, f"Send failed: {resp.text[:200]}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Send failed: {e}")

    return {"sent": True, "to": body.to, "subject": f"[TEST PREVIEW] {subject_str}"}


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

        # Decode checks from latest scan (may be jsonb list or legacy json string)
        latest_checks = []
        if latest_scan:
            raw = latest_scan.get("checks", [])
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    raw = []
            latest_checks = raw if isinstance(raw, list) else []

        # Decode cached contact_emails if stored as JSON string
        cached_contact_emails = d.get("contact_emails")
        if isinstance(cached_contact_emails, str):
            try:
                cached_contact_emails = json.loads(cached_contact_emails)
            except Exception:
                cached_contact_emails = []

        result.append({
            "id":              d["id"],
            "domain":          d["domain"],
            "country":         d["country"],
            "added":           d["created_at"],
            "status":          status,
            "paid":            is_paid,
            "risk_score":      latest_scan["risk_score"] if latest_scan else None,
            "scanned_at":      latest_scan["scanned_at"] if latest_scan else None,
            "checks":          latest_checks,
            "primary_contact": d.get("primary_contact"),
            "contact_emails":  cached_contact_emails or [],
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

    # Free tier: 10 domains max unless user has an active paid plan or is admin
    FREE_DOMAIN_LIMIT = 10
    if not is_admin(user["sub"]):
        domain_count = db.table("domains").select("id", count="exact").eq("user_id", user["sub"]).execute()
        if (domain_count.count or 0) >= FREE_DOMAIN_LIMIT:
            paid = db.table("purchases").select("id")\
                .eq("user_id", user["sub"])\
                .is_("cancelled_at", "null")\
                .not_.is_("paid_at", "null")\
                .execute()
            if not paid.data:
                raise HTTPException(
                    status_code=403,
                    detail=f"Free accounts are limited to {FREE_DOMAIN_LIMIT} domains. Upgrade to Annual ($50/year) to monitor unlimited domains."
                )

    # Resolve country — use provided value only when it's a real ISO code
    resolved_country = body.country.upper().strip() if body.country else ""
    if not resolved_country or resolved_country in ("EU", "??", ""):
        resolved_country = tld_to_country(body.domain.lower())

    # Insert domain
    result = db.table("domains").insert({
        "user_id":    user["sub"],
        "domain":     body.domain.lower(),
        "country":    resolved_country,
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


@app.get("/domains/{domain_id}/contacts")
def get_domain_contacts(domain_id: str, authorization: str = Header(None)):
    """Discover contact emails for a domain (security.txt, WHOIS, website scrape)."""
    user = get_user_from_header(authorization)
    db   = get_db()
    row  = db.table("domains").select("id,domain,user_id,primary_contact,contact_emails")\
             .eq("id", domain_id).execute()
    if not row.data or row.data[0]["user_id"] != user["sub"]:
        raise HTTPException(404, "Domain not found")
    d = row.data[0]

    # Return cached contacts if available (re-discover if none)
    cached = d.get("contact_emails")
    if cached:
        try:
            contacts = json.loads(cached) if isinstance(cached, str) else cached
        except Exception:
            contacts = []
    else:
        contacts = []

    return {
        "domain":          d["domain"],
        "primary_contact": d.get("primary_contact") or (contacts[0] if contacts else None),
        "contacts":        contacts,
    }


@app.post("/domains/{domain_id}/contacts/discover")
async def discover_domain_contacts(domain_id: str, authorization: str = Header(None)):
    """Run fresh contact discovery for a domain and cache results."""
    import asyncio
    user = get_user_from_header(authorization)
    db   = get_db()
    row  = db.table("domains").select("id,domain,user_id,primary_contact")\
             .eq("id", domain_id).execute()
    if not row.data or row.data[0]["user_id"] != user["sub"]:
        raise HTTPException(404, "Domain not found")
    d = row.data[0]

    try:
        from outreach import discover_all_contacts
        contacts = await asyncio.get_event_loop().run_in_executor(
            None, discover_all_contacts, d["domain"]
        )
    except ImportError:
        from swarmhawk_backend.outreach import discover_all_contacts
        contacts = await asyncio.get_event_loop().run_in_executor(
            None, discover_all_contacts, d["domain"]
        )

    db.table("domains").update({"contact_emails": json.dumps(contacts)}).eq("id", domain_id).execute()

    # Set primary_contact to best discovered address if not already set
    primary = d.get("primary_contact") or (contacts[0] if contacts else None)

    return {
        "domain":          d["domain"],
        "primary_contact": primary,
        "contacts":        contacts,
    }


@app.patch("/domains/{domain_id}/contact")
def set_domain_contact(domain_id: str, body: DomainContactRequest, authorization: str = Header(None)):
    """Set the primary outreach contact email for a domain (user-editable).
    Also ensures the email is in the contact_emails list and syncs to outreach_prospects."""
    user = get_user_from_header(authorization)
    db   = get_db()
    row  = db.table("domains").select("id,domain,user_id,contact_emails").eq("id", domain_id).execute()
    if not row.data or row.data[0]["user_id"] != user["sub"]:
        raise HTTPException(404, "Domain not found")
    d = row.data[0]
    email = (body.primary_contact or "").strip()
    if not email or "@" not in email:
        raise HTTPException(400, "Invalid email address")

    # Merge email into contact_emails list (no duplicates)
    raw = d.get("contact_emails") or "[]"
    try:
        emails_list = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except Exception:
        emails_list = []
    if email not in emails_list:
        emails_list.insert(0, email)

    res = db.table("domains").update({
        "primary_contact": email,
        "contact_emails":  json.dumps(emails_list),
    }).eq("id", domain_id).execute()

    if hasattr(res, "error") and res.error:
        raise HTTPException(500, f"Database error: {res.error}")

    domain_name = d.get("domain", "")
    # Sync to outreach_prospects if this domain exists there
    try:
        db.table("outreach_prospects").update({"contact_email": email})\
          .eq("domain", domain_name).execute()
    except Exception:
        pass  # outreach_prospects row may not exist — that's fine

    return {"status": "saved", "primary_contact": email, "contacts": emails_list}


@app.post("/domains/{domain_id}/contacts/add")
def add_domain_contact(domain_id: str, body: DomainContactAddRequest, authorization: str = Header(None)):
    """Add an email to the domain's contact list (does not change primary)."""
    user = get_user_from_header(authorization)
    db   = get_db()
    row  = db.table("domains").select("id,domain,user_id,primary_contact,contact_emails")\
             .eq("id", domain_id).execute()
    if not row.data or row.data[0]["user_id"] != user["sub"]:
        raise HTTPException(404, "Domain not found")
    d = row.data[0]
    email = (body.email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Invalid email address")

    raw = d.get("contact_emails") or "[]"
    try:
        emails_list = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except Exception:
        emails_list = []
    if email in emails_list:
        return {"status": "exists", "contacts": emails_list, "primary_contact": d.get("primary_contact")}

    emails_list.append(email)
    db.table("domains").update({"contact_emails": json.dumps(emails_list)}).eq("id", domain_id).execute()

    # If no primary contact set yet, set this one
    primary = d.get("primary_contact")
    if not primary:
        db.table("domains").update({"primary_contact": email}).eq("id", domain_id).execute()
        primary = email
        try:
            db.table("outreach_prospects").update({"contact_email": email})\
              .eq("domain", d.get("domain", "")).execute()
        except Exception:
            pass

    return {"status": "added", "contacts": emails_list, "primary_contact": primary}


@app.delete("/domains/{domain_id}/contacts/{email:path}")
def remove_domain_contact(domain_id: str, email: str, authorization: str = Header(None)):
    """Remove an email from the domain's contact list."""
    user = get_user_from_header(authorization)
    db   = get_db()
    row  = db.table("domains").select("id,domain,user_id,primary_contact,contact_emails")\
             .eq("id", domain_id).execute()
    if not row.data or row.data[0]["user_id"] != user["sub"]:
        raise HTTPException(404, "Domain not found")
    d = row.data[0]
    email = email.strip()

    raw = d.get("contact_emails") or "[]"
    try:
        emails_list = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except Exception:
        emails_list = []
    emails_list = [e for e in emails_list if e != email]

    update = {"contact_emails": json.dumps(emails_list)}
    # If we removed the primary, promote the next one (or clear)
    primary = d.get("primary_contact")
    if primary == email:
        primary = emails_list[0] if emails_list else None
        update["primary_contact"] = primary
        if primary:
            try:
                db.table("outreach_prospects").update({"contact_email": primary})\
                  .eq("domain", d.get("domain", "")).execute()
            except Exception:
                pass

    db.table("domains").update(update).eq("id", domain_id).execute()
    return {"status": "removed", "contacts": emails_list, "primary_contact": primary}


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
    FREE_CHECKS = {
        "ssl", "headers", "dns", "https_redirect", "breach", "typosquat", "performance",
        "urlhaus", "spamhaus", "safebrowsing", "virustotal", "cve", "darkweb",
        "whois", "email_security", "shodan", "open_ports", "sast", "sca", "dast", "iac",
        # paid: ip_intel
    }

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


@app.get("/domains/{domain_id}/history")
def get_domain_history(domain_id: str, authorization: str = Header(None)):
    """Return full scan history for a domain (owner only)."""
    user = get_user_from_header(authorization)
    db   = get_db()
    d = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data:
        raise HTTPException(404, "Domain not found")
    if d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not your domain")
    scans = db.table("scans")\
        .select("risk_score,critical,warnings,scanned_at")\
        .eq("domain_id", domain_id)\
        .order("scanned_at", desc=True)\
        .limit(50)\
        .execute()
    return {"domain": d.data[0]["domain"], "scans": scans.data or []}


# ── PDF report generation ──────────────────────────────────────────────────────

def _pdf_safe(text: str) -> str:
    """Translate common Unicode chars to Latin-1 equivalents so FPDF Helvetica doesn't crash."""
    if not text:
        return ""
    replacements = {
        "\u2014": "-",  "\u2013": "-",   # em dash, en dash
        "\u2018": "'",  "\u2019": "'",   # left/right single quotes
        "\u201c": '"',  "\u201d": '"',   # left/right double quotes
        "\u2022": "*",  "\u2026": "...", # bullet, ellipsis
        "\u00b7": ".",  "\u2019": "'",
        "\u2122": "(TM)", "\u00ae": "(R)", "\u00a9": "(C)",
        "\u00d7": "x",  "\u00f7": "/",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    # Strip any remaining non-Latin-1 characters
    return text.encode("latin-1", errors="replace").decode("latin-1")


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
    pdf.cell(0, 8, "SWARMHAWK - Security Report", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, _pdf_safe(f"Generated {scan_date}  |  European Cybersecurity Intelligence"), ln=True)

    pdf.set_y(40)

    # ── Domain + score ──────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 20)
    score_col = (192, 57, 43) if risk_score >= 60 else (212, 133, 10) if risk_score >= 30 else (26, 122, 74)
    pdf.set_text_color(*score_col)
    pdf.cell(0, 10, f"Risk Score: {risk_score}/100", ln=True)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, _pdf_safe(domain), ln=True)
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
        "https_redirect": "HTTPS Redirect", "breach": "Breach Exposure",
        "typosquat": "Typosquat", "performance": "Response Time",
        "email_security": "Email Security", "whois": "WHOIS / RDAP",
        "urlhaus": "URLhaus Malware", "spamhaus": "Spamhaus DBL",
        "safebrowsing": "Safe Browsing", "virustotal": "VirusTotal",
        "cve": "CVE Scan", "darkweb": "Dark Web Leaks",
        "ip_intel": "IP Intelligence", "shodan": "Shodan",
        "open_ports": "Open Ports", "sast": "SAST — Source Exposure",
        "sca": "SCA — Dependency CVEs", "dast": "DAST — App Testing",
        "iac": "IaC — Config Exposure",
    }

    for c in non_ai:
        status = c.get("status", "ok")
        label  = _pdf_safe(CHECK_LABELS.get(c.get("check", ""), c.get("check", "").replace("_", " ").upper()))
        title  = _pdf_safe(c.get("title", ""))
        detail = _pdf_safe(c.get("detail", ""))

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
    pdf.cell(0, 5, "SwarmHawk - European Cybersecurity Intelligence - www.swarmhawk.com", ln=True, align="C")
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

    # Resolve custom or default template
    tpl = _get_report_email_template()
    tpl_vars = dict(
        domain=d['domain'], risk_score=risk_score, score_label=score_label,
        criticals=criticals, warnings=warnings, checks_count=len(non_ai),
        scanned_at=scanned_at[:10],
    )
    try:
        subject = tpl["subject"].format(**tpl_vars)
    except (KeyError, ValueError):
        subject = f"Security Report: {d['domain']} — {score_label} ({risk_score}/100)"
    try:
        body_text = tpl["body"].format(**tpl_vars)
    except (KeyError, ValueError):
        body_text = f"Your full security report for <strong>{d['domain']}</strong> is attached as a PDF."
    try:
        footer_text = (tpl.get("footer") or _REPORT_EMAIL_DEFAULTS["footer"]).format(**tpl_vars)
    except (KeyError, ValueError):
        footer_text = _REPORT_EMAIL_DEFAULTS["footer"]

    score_color = '#c0392b' if risk_score >= 60 else '#d4850a' if risk_score >= 30 else '#1a7a4a'
    email_html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a0a;color:#fff;border-radius:8px;overflow:hidden">

      <!-- Header -->
      <div style="background:#0e0d12;padding:28px 36px;border-bottom:1px solid #1a1a1a">
        <span style="font-family:monospace;font-size:18px;font-weight:700;color:#cbff00">&#9679;SWARMHAWK</span>
        <span style="font-family:monospace;font-size:11px;color:#444;margin-left:12px">European Cybersecurity Intelligence</span>
      </div>

      <!-- Body -->
      <div style="padding:32px 36px">
        <h2 style="color:#fff;margin:0 0 4px 0;font-size:20px">Security Report: {d['domain']}</h2>
        <p style="color:#666;font-size:12px;margin:0 0 24px 0;font-family:monospace">Scanned {scanned_at[:10]}</p>

        <!-- Score card -->
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:8px;padding:20px 24px;margin-bottom:24px;display:flex;align-items:center;gap:28px">
          <div style="text-align:center;min-width:60px">
            <div style="font-size:36px;font-weight:800;color:{score_color};line-height:1">{risk_score}</div>
            <div style="font-size:10px;color:#888;font-family:monospace;margin-top:4px">{score_label}</div>
          </div>
          <div style="border-left:1px solid #2a2a2a;padding-left:24px;flex:1">
            <div style="color:#c0392b;font-weight:700;font-size:14px">{criticals} Critical</div>
            <div style="color:#d4850a;font-weight:700;font-size:14px">{warnings} Warnings</div>
            <div style="color:#555;font-size:12px;margin-top:6px">{len(non_ai)} checks run</div>
          </div>
        </div>

        <!-- PDF attachment notice -->
        <div style="background:#111;border:1px solid #1e3a1e;border-radius:6px;padding:14px 18px;margin-bottom:20px;display:flex;align-items:center;gap:12px">
          <span style="font-size:22px">&#128196;</span>
          <div>
            <div style="color:#cbff00;font-family:monospace;font-size:11px;font-weight:700;letter-spacing:1px">PDF REPORT ATTACHED</div>
            <div style="color:#888;font-size:12px;margin-top:2px">{filename} — full findings, risk breakdown &amp; remediation steps</div>
          </div>
        </div>

        <!-- Body message -->
        <p style="color:#aaa;font-size:13px;line-height:1.7;margin-bottom:28px">{body_text}</p>

        <!-- CTAs -->
        <div style="margin-bottom:28px">
          <a href="https://www.swarmhawk.com" style="display:inline-block;background:#cbff00;color:#000;font-family:monospace;font-weight:700;font-size:13px;padding:13px 26px;border-radius:6px;text-decoration:none;margin-right:12px;margin-bottom:10px">Get Free Account &#8594;</a>
          <a href="https://www.swarmhawk.com" style="display:inline-block;background:transparent;color:#cbff00;font-family:monospace;font-weight:700;font-size:13px;padding:12px 26px;border-radius:6px;text-decoration:none;border:1px solid #cbff00;margin-bottom:10px">Full Paid Report &#8594;</a>
        </div>

        <!-- Feature bullets -->
        <div style="background:#0d0d0d;border:1px solid #1a1a1a;border-radius:6px;padding:16px 20px;margin-bottom:24px">
          <div style="font-family:monospace;font-size:10px;color:#555;letter-spacing:1px;text-transform:uppercase;margin-bottom:10px">What you get with SwarmHawk</div>
          <div style="font-size:12px;color:#888;line-height:2">
            &#10003; &nbsp;Continuous domain monitoring &amp; re-scans<br>
            &#10003; &nbsp;Instant alerts on new critical threats<br>
            &#10003; &nbsp;NIS2 / DORA compliance autopilot<br>
            &#10003; &nbsp;Monthly PDF reports &amp; audit evidence<br>
            &#10003; &nbsp;AI threat intelligence briefings
          </div>
        </div>
      </div>

      <!-- Footer -->
      <div style="background:#0e0d12;border-top:1px solid #1a1a1a;padding:18px 36px">
        <p style="color:#444;font-size:11px;margin:0;line-height:1.7">{footer_text}</p>
      </div>

    </div>
    """

    try:
        import httpx as _httpx
        resp = _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from":    f"SwarmHawk Reports <{REPORT_FROM_EMAIL}>",
                "to":      [body.email],
                "subject": subject,
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


def _resolve_stripe_customer(db, user_id: str) -> str | None:
    """Return a Stripe customer ID for the user, trying purchases first, then email lookup."""
    purchases = db.table("purchases").select("stripe_session_id")\
        .eq("user_id", user_id).not_.is_("stripe_session_id", "null").limit(5).execute()
    if purchases.data:
        for p in purchases.data:
            try:
                session = stripe.checkout.Session.retrieve(p["stripe_session_id"])
                if session.customer:
                    return session.customer
            except Exception:
                continue
    # Fallback: look up by email
    u_row = db.table("users").select("email").eq("id", user_id).execute()
    email = u_row.data[0]["email"] if u_row.data else None
    if email:
        customers = stripe.Customer.list(email=email, limit=1)
        if customers.data:
            return customers.data[0].id
    return None


@app.get("/billing-portal")
def billing_portal(authorization: str = Header(None)):
    """Return a Stripe Customer Portal URL so users can manage subscriptions and payment methods."""
    user = get_user_from_header(authorization)
    db   = get_db()

    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe not configured")

    purchases = db.table("purchases").select("stripe_session_id")\
        .eq("user_id", user["sub"]).not_.is_("stripe_session_id", "null").limit(1).execute()
    if not purchases.data:
        raise HTTPException(400, "No billing history found — purchase a plan first")

    try:
        customer = _resolve_stripe_customer(db, user["sub"])
        if not customer:
            raise HTTPException(400, "No Stripe customer record found")
        portal = stripe.billing_portal.Session.create(
            customer=customer, return_url=FRONTEND_URL
        )
        return {"url": portal.url}
    except stripe.error.StripeError as e:
        raise HTTPException(400, str(e))


@app.get("/billing-portal/api")
def billing_portal_api(authorization: str = Header(None)):
    """Return a Stripe Customer Portal URL for managing an API plan subscription."""
    user = get_user_from_header(authorization)
    db   = get_db()

    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe not configured")

    try:
        customer = _resolve_stripe_customer(db, user["sub"])
        if not customer:
            raise HTTPException(400, "No Stripe customer record found — complete a purchase first")
        portal = stripe.billing_portal.Session.create(
            customer=customer,
            return_url=f"{FRONTEND_URL}?tab=account",
        )
        return {"url": portal.url}
    except stripe.error.StripeError as e:
        raise HTTPException(400, str(e))


@app.get("/checkout/preflight")
def checkout_preflight(authorization: str = Header(None)):
    """Debug: verify all checkout prerequisites without hitting Stripe."""
    user = get_user_from_header(authorization)
    db   = get_db()
    doms = db.table("domains").select("id,domain").eq("user_id", user["sub"]).execute()
    return {
        "auth": "ok",
        "user_id": user["sub"],
        "stripe_configured": bool(STRIPE_SECRET_KEY),
        "frontend_url": FRONTEND_URL,
        "domains": [{"id": d["id"], "domain": d["domain"]} for d in (doms.data or [])],
    }


@app.post("/checkout")
def create_checkout(body: CheckoutRequest, authorization: str = Header(None)):
    """
    Create a Stripe Checkout session.
    plan=one_time  → $10 one-time payment, unlocks full report permanently.
    plan=annual    → $50/year subscription, monthly auto-scans + reports.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe not configured — set STRIPE_SECRET_KEY in environment")

    user = get_user_from_header(authorization)
    db   = get_db()

    # Fetch email from users table (get_user_from_header only returns sub/id)
    u_row = db.table("users").select("email").eq("id", user["sub"]).execute()
    user_email = u_row.data[0]["email"] if u_row.data else ""

    if body.plan not in ("one_time", "annual"):
        raise HTTPException(400, "plan must be 'one_time' or 'annual'")

    domain_row = db.table("domains")\
        .select("id, domain")\
        .eq("id", body.domain_id)\
        .eq("user_id", user["sub"])\
        .limit(1)\
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
                            "description": "Full 22-check security report with AI threat analysis. One-time purchase.",
                        },
                    },
                    "quantity": 1,
                }],
                success_url=f"{FRONTEND_URL}?payment=success&domain_id={body.domain_id}",
                cancel_url=f"{FRONTEND_URL}?payment=cancelled",
                metadata=meta,
                customer_email=user_email,
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
                customer_email=user_email,
                subscription_data={"metadata": meta},
            )

        return {"url": session.url, "session_id": session.id, "plan": body.plan}

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

        if plan.startswith("api_") and user_id:
            # API pricing plan — record purchase (no domain) and apply limit
            sub_id = session.get("subscription")
            now = datetime.now(timezone.utc).isoformat()
            try:
                db.table("purchases").insert({
                    "user_id":           user_id,
                    "stripe_session_id": session["id"],
                    "stripe_sub_id":     sub_id,
                    "amount_usd":        (session.get("amount_total") or _API_PLAN_AMOUNTS.get(plan, 0)) / 100,
                    "plan":              plan,
                    "domain":            "api_plan",
                    "paid_at":           now,
                }).execute()
            except Exception:
                pass
            _apply_api_plan(db, user_id, plan)

        elif user_id and domain_id:
            sub_id = session.get("subscription")   # None for one-time
            _record_purchase(
                db, user_id, domain_id, domain,
                session["id"],
                session.get("amount_total") or (1000 if plan == "one_time" else 5000),
                plan,
                subscription_id=sub_id,
            )

    # ── Subscription renewal ──────────────────────────────────────────────────
    elif event["type"] == "invoice.payment_succeeded":
        invoice = event["data"]["object"]
        sub_id  = invoice.get("subscription")
        if invoice.get("billing_reason") == "subscription_cycle" and sub_id:
            purchases = db.table("purchases").select("domain_id, domain, user_id, plan")\
                .eq("stripe_sub_id", sub_id).limit(1).execute()
            if purchases.data:
                p = purchases.data[0]
                if (p.get("plan") or "").startswith("api_"):
                    # API plan renewal — reset monthly call counter
                    db.table("api_keys").update({"calls_this_month": 0})\
                        .eq("user_id", p["user_id"]).execute()
                    print(f"[stripe] API plan renewed, calls reset for user {p['user_id']}")
                else:
                    # Domain subscription renewal — queue rescan
                    db.table("domains").update({"full_scan_enabled": True}).eq("id", p["domain_id"]).execute()
                    from threading import Thread
                    Thread(target=run_scan_background, args=(p["domain_id"], p.get("domain", "")), daemon=True).start()
                    print(f"[stripe] Subscription renewal scan queued for {p.get('domain')}")

    # ── Subscription cancelled ────────────────────────────────────────────────
    elif event["type"] == "customer.subscription.deleted":
        sub    = event["data"]["object"]
        sub_id = sub.get("id")
        if sub_id:
            now = datetime.now(timezone.utc).isoformat()
            db.table("purchases").update({"cancelled_at": now})\
                .eq("stripe_sub_id", sub_id).execute()
            # If this was an API plan, downgrade the user's key limits
            purchases = db.table("purchases").select("user_id, plan")\
                .eq("stripe_sub_id", sub_id).limit(1).execute()
            if purchases.data and (purchases.data[0].get("plan") or "").startswith("api_"):
                _apply_api_plan(db, purchases.data[0]["user_id"], "free")
            print(f"[stripe] Subscription cancelled: {sub_id}")

    return {"received": True}


# ── LLM gateway (Portkey-routed or direct Anthropic) ─────────────────────────

def _build_anthropic_headers(api_key: str, metadata: dict | None = None) -> dict:
    """Return headers for Anthropic call, optionally routed via Portkey."""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    if PORTKEY_API_KEY:
        headers["x-portkey-api-key"] = PORTKEY_API_KEY
        headers["x-portkey-provider"] = "anthropic"
        if metadata:
            import json as _json
            headers["x-portkey-metadata"] = _json.dumps(metadata)
    return headers

def _anthropic_url() -> str:
    """Return the correct Anthropic-compatible URL (Portkey gateway or direct)."""
    if PORTKEY_API_KEY:
        return "https://api.portkey.ai/v1/messages"
    return "https://api.anthropic.com/v1/messages"

def _call_claude_sync(api_key: str, model: str, max_tokens: int,
                      system: str, messages: list, metadata: dict | None = None) -> dict:
    """Synchronous Claude call via Portkey gateway or direct Anthropic."""
    import requests as _req
    r = _req.post(
        _anthropic_url(),
        headers=_build_anthropic_headers(api_key, metadata),
        json={"model": model, "max_tokens": max_tokens, "system": system, "messages": messages},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()

async def _call_claude_async(api_key: str, model: str, max_tokens: int,
                              system: str, messages: list, metadata: dict | None = None) -> dict:
    """Async Claude call via Portkey gateway or direct Anthropic."""
    import httpx
    async with httpx.AsyncClient(timeout=35) as client:
        r = await client.post(
            _anthropic_url(),
            headers=_build_anthropic_headers(api_key, metadata),
            json={"model": model, "max_tokens": max_tokens, "system": system, "messages": messages},
        )
    r.raise_for_status()
    return r.json()


# ── Background scan ───────────────────────────────────────────────────────────

def _generate_ai_summary(domain: str, result: dict, user_id: str | None = None) -> str | None:
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
        data = _call_claude_sync(
            api_key=AKEY,
            model="claude-haiku-4-5-20251001",
            max_tokens=700,
            system="You are a cybersecurity analyst. Output only the report text in the exact format requested. No markdown, no backticks, no extra commentary.",
            messages=[{"role": "user", "content": prompt}],
            metadata={"report_type": "domain_scan", "domain": domain, "_user": user_id or "system"},
        )
        return data["content"][0]["text"] if data.get("content") else None
    except Exception as e:
        print(f"AI summary generation failed for {domain}: {e}")
    return None


def run_scan_background(domain_id: str, domain: str):
    """Run scanner in background and save results to DB."""
    _active_scans[domain_id] = {"domain": domain, "started_at": datetime.now(timezone.utc).isoformat(), "user_id": None, "status": "scanning"}
    try:
        if not SCANNER_AVAILABLE:
            print(f"Scan skipped for {domain}: cee_scanner not installed on this server")
            return
        from cee_scanner.checks import scan_domain

        # Fetch owner early so user_id is available for AI summary metadata
        db = get_db()
        domain_owner = db.table("domains").select("user_id").eq("id", domain_id).execute()
        owner_user_id = domain_owner.data[0]["user_id"] if domain_owner.data else None
        _active_scans[domain_id]["user_id"] = owner_user_id

        result = scan_domain(domain)

        # Generate AI Intelligence Report (requires ANTHROPIC_API_KEY env var)
        ai_text = _generate_ai_summary(domain, result, user_id=owner_user_id)
        if ai_text:
            result["checks"].append({
                "check": "ai_summary",
                "status": "ok",
                "title": "AI Intelligence Report",
                "detail": ai_text,
                "score_impact": 0,
            })

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

        # Look up domain owner email (user_id already fetched above)
        user_id    = owner_user_id
        user_row   = db.table("users").select("email").eq("id", user_id).execute() if user_id else None
        user_email = user_row.data[0]["email"] if (user_row and user_row.data) else None

        if user_email:
            # ── Alert: risk spike or new critical threats ────────────────────
            prev_scans = db.table("scans").select("risk_score,checks")\
                .eq("domain_id", domain_id).order("scanned_at", desc=True).limit(2).execute()
            if len(prev_scans.data) >= 2:
                prev       = prev_scans.data[1]  # second-most-recent
                prev_score = prev.get("risk_score") or 0
                new_score  = result["risk_score"]
                prev_raw   = prev.get("checks", [])
                if isinstance(prev_raw, str):
                    try: prev_raw = json.loads(prev_raw)
                    except: prev_raw = []
                prev_checks = {c["check"]: c["status"] for c in prev_raw}
                THREAT_CHECKS = {"urlhaus", "spamhaus", "virustotal", "safebrowsing"}
                new_threats = [
                    c["title"] for c in result["checks"]
                    if c.get("check") in THREAT_CHECKS
                    and c.get("status") == "critical"
                    and prev_checks.get(c.get("check")) != "critical"
                ]
                if new_score - prev_score >= 15 or new_threats:
                    from threading import Thread
                    Thread(target=send_alert_email,
                           args=(user_email, domain, prev_score, new_score, new_threats),
                           daemon=True).start()

            # ── Monthly PDF: send to annual subscribers ──────────────────────
            active_sub = db.table("purchases").select("id")\
                .eq("user_id", user_id).eq("plan", "annual")\
                .is_("cancelled_at", "null").not_.is_("paid_at", "null").execute()
            if active_sub.data:
                from threading import Thread
                Thread(target=send_monthly_pdf_email,
                       args=(user_email, domain, result["risk_score"],
                             result["scanned_at"], result["checks"]),
                       daemon=True).start()
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
    finally:
        _active_scans.pop(domain_id, None)


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
    domain: str = ""
    max_tokens: int = 1000

@app.post("/intel")
async def intel(body: IntelRequest, authorization: str = Header(None)):
    """Generate AI threat briefing using server-side ANTHROPIC_API_KEY."""
    user = get_user_from_header(authorization)

    AKEY = os.getenv("ANTHROPIC_API_KEY", "")
    if not AKEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured on server")

    # Use custom prompt (outreach) or build briefing prompt (intelligence tab)
    report_type = "outreach_email" if body.prompt else "intel_briefing"
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
            '{"title":"European Regional","body":"2 sentences"},'
            '{"title":"Vulnerabilities","body":"2 sentences"},'
            '{"title":"Phishing","body":"2 sentences"},'
            '{"title":"Compliance","body":"2 sentences"},'
            '{"title":"Recommendations","body":"3 action items"}]}'
        )
        system  = "You are a cybersecurity analyst. Output valid JSON only, no markdown, no backticks."
        max_tok = 1000

    # Resolve domain for metadata — explicit field takes priority, else first domain from briefing list
    meta_domain = body.domain or (body.domains.split(",")[0].strip() if body.domains else "")

    try:
        data = await _call_claude_async(
            api_key=AKEY,
            model="claude-haiku-4-5-20251001",
            max_tokens=max_tok,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            metadata={"report_type": report_type, "_user": user["sub"], "domain": meta_domain},
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM error: {str(e)[:200]}")

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
        FREE_CHECKS = {"ssl", "headers", "dns", "shodan", "open_ports", "sast", "sca", "dast", "iac", "darkweb"}
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


# ══════════════════════════════════════════════════════════════════════════════
# DEVELOPER API  — /api/v1/*
# Rate: 10 free scans/month per key. Paid: unlimited via annual plan.
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_api_key(api_key: str) -> dict:
    """Return user row for a valid API key. Raises 401/429 on failure."""
    if not api_key:
        raise HTTPException(401, "Missing X-API-Key header")
    db = get_db()
    row = db.table("api_keys").select("user_id, calls_this_month, limit_per_month, active")\
        .eq("key", api_key).execute()
    if not row.data:
        raise HTTPException(401, "Invalid API key")
    r = row.data[0]
    if not r.get("active", True):
        raise HTTPException(403, "API key disabled")
    limit = r.get("limit_per_month") or 10
    used  = r.get("calls_this_month") or 0
    if used >= limit:
        raise HTTPException(429, f"Monthly API limit reached ({limit} calls). Upgrade at swarmhawk.com")
    return r


@app.post("/api/v1/scan")
async def api_scan(request: Request, background_tasks: BackgroundTasks):
    """
    Full domain scan. Accepts either:
      - X-API-Key: <key>            (developer API)
      - Authorization: Bearer <tok> (logged-in dashboard users)

    Body: { "domain": "example.com" }
    Returns: { "domain", "risk_score", "critical", "warnings", "checks", "scanned_at" }
    """
    api_key  = request.headers.get("X-API-Key", "")
    auth_hdr = request.headers.get("Authorization", "")
    db = get_db()

    if api_key:
        # Developer API path — rate-limited by API key
        user = _resolve_api_key(api_key)
        db.table("api_keys").update({"calls_this_month": (user.get("calls_this_month") or 0) + 1})\
            .eq("key", api_key).execute()
    elif auth_hdr.startswith("Bearer "):
        # Session-authenticated dashboard user — no API key needed
        user = get_user_from_header(auth_hdr)
    else:
        raise HTTPException(401, "Missing X-API-Key header or Authorization token")

    body    = await request.json()
    domain  = (body.get("domain") or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")

    if not SCANNER_AVAILABLE:
        raise HTTPException(503, "Scanner not available on this instance")

    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)
        api_user_id = user.get("user_id") or user.get("sub") or "api_user"
        ai_text = _generate_ai_summary(domain, result, user_id=api_user_id)
        if ai_text:
            result["checks"].append({
                "check": "ai_summary", "status": "ok",
                "title": "AI Intelligence Report", "detail": ai_text, "score_impact": 0,
            })
        return {
            "domain":     domain,
            "risk_score": result["risk_score"],
            "critical":   result["critical"],
            "warnings":   result["warnings"],
            "checks":     result["checks"],
            "scanned_at": result["scanned_at"],
        }
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)[:200]}")


@app.post("/api/v1/keys")
def create_api_key(authorization: str = Header(None)):
    """Generate a new API key. If the user already has one, return it instead of creating a duplicate."""
    user = get_user_from_header(authorization)
    db   = get_db()
    existing = db.table("api_keys").select("key,calls_this_month,limit_per_month,active,created_at")\
        .eq("user_id", user["sub"]).eq("active", True).execute()
    if existing.data:
        return {"keys": existing.data, "created": False}
    new_key = "swh_" + secrets.token_hex(24)
    db.table("api_keys").insert({
        "key":              new_key,
        "user_id":          user["sub"],
        "calls_this_month": 0,
        "limit_per_month":  10,
        "active":           True,
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }).execute()
    return {"keys": [{"key": new_key, "calls_this_month": 0, "limit_per_month": 10, "active": True}], "created": True}


@app.get("/api/v1/keys")
def list_api_keys(authorization: str = Header(None)):
    """List API keys and usage for the current user."""
    user = get_user_from_header(authorization)
    db   = get_db()
    rows = db.table("api_keys").select("key,calls_this_month,limit_per_month,active,created_at")\
        .eq("user_id", user["sub"]).execute()
    return {"keys": rows.data or []}


@app.post("/api/v1/keys/{key}/regenerate")
def regenerate_api_key(key: str, authorization: str = Header(None)):
    """Revoke the given key and issue a fresh one, preserving the usage limit."""
    user = get_user_from_header(authorization)
    db   = get_db()
    existing = db.table("api_keys").select("limit_per_month")\
        .eq("key", key).eq("user_id", user["sub"]).execute()
    if not existing.data:
        raise HTTPException(404, "Key not found")
    limit = existing.data[0].get("limit_per_month") or 10
    db.table("api_keys").delete().eq("key", key).eq("user_id", user["sub"]).execute()
    new_key = "swh_" + secrets.token_hex(24)
    db.table("api_keys").insert({
        "key":              new_key,
        "user_id":          user["sub"],
        "calls_this_month": 0,
        "limit_per_month":  limit,
        "active":           True,
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }).execute()
    return {"key": new_key, "calls_this_month": 0, "limit_per_month": limit}


@app.delete("/api/v1/keys/{key}")
def revoke_api_key(key: str, authorization: str = Header(None)):
    """Permanently delete an API key."""
    user = get_user_from_header(authorization)
    db   = get_db()
    db.table("api_keys").delete().eq("key", key).eq("user_id", user["sub"]).execute()
    return {"revoked": key}


# ══════════════════════════════════════════════════════════════════════════════
# NIS2 COMPLIANCE MODULE
# Maps existing check results → EU NIS2 Article 21 compliance score
# ══════════════════════════════════════════════════════════════════════════════

NIS2_MAPPING = {
    # check_name → (article, requirement, weight)
    "ssl":            ("Art.21(2)(i)", "Encryption & TLS security",        3),
    "headers":        ("Art.21(2)(i)", "Transport security controls",       2),
    "email_security": ("Art.21(2)(i)", "Email authentication (SPF/DKIM)",   2),
    "dmarc":          ("Art.21(2)(i)", "Email anti-spoofing (DMARC)",       2),
    "dnssec":         ("Art.21(2)(h)", "DNS security extensions",           2),
    "open_ports":     ("Art.21(2)(e)", "Network access control",            3),
    "shodan":         ("Art.21(2)(e)", "Attack surface management",         2),
    "virustotal":     ("Art.21(2)(b)", "Incident detection & response",     3),
    "urlhaus":        ("Art.21(2)(b)", "Malware & threat detection",        3),
    "spamhaus":       ("Art.21(2)(b)", "Threat intelligence",               2),
    "safebrowsing":   ("Art.21(2)(b)", "Phishing protection",               2),
    "typosquat":      ("Art.21(2)(f)", "Brand & supply chain protection",   2),
    "ip_intel":       ("Art.21(2)(e)", "Network security monitoring",       2),
    "leaks":          ("Art.21(2)(g)", "Data protection & breach prevent.", 3),
    "cms_version":    ("Art.21(2)(e)", "Software vulnerability management", 2),
    "dast":           ("Art.21(2)(e)", "Application security testing",      2),
}


@app.get("/domains/{domain_id}/nis2")
def get_nis2_compliance(domain_id: str, authorization: str = Header(None)):
    """
    Return a NIS2 Article 21 compliance score for a domain.
    Maps each security check to the relevant NIS2 requirement.
    """
    user = get_user_from_header(authorization)
    db   = get_db()
    d = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data or d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found or not your domain")

    scan = db.table("scans").select("checks,risk_score,scanned_at")\
        .eq("domain_id", domain_id).order("scanned_at", desc=True).limit(1).execute()
    if not scan.data:
        raise HTTPException(404, "No scan data yet")

    raw = scan.data[0].get("checks", []) or []
    if isinstance(raw, str):
        try: raw = json.loads(raw)
        except: raw = []

    check_map = {c.get("check"): c for c in raw}
    findings  = []
    total_weight = 0
    pass_weight  = 0

    for check_name, (article, requirement, weight) in NIS2_MAPPING.items():
        c = check_map.get(check_name)
        status = c.get("status", "unknown") if c else "unknown"
        passed = status in ("ok", "info")
        total_weight += weight
        if passed:
            pass_weight += weight
        findings.append({
            "check":       check_name,
            "article":     article,
            "requirement": requirement,
            "status":      status,
            "passed":      passed,
            "weight":      weight,
        })

    compliance_pct = round(pass_weight / total_weight * 100) if total_weight else 0
    rating = "COMPLIANT" if compliance_pct >= 80 else "PARTIAL" if compliance_pct >= 50 else "NON-COMPLIANT"

    return {
        "domain":         d.data[0]["domain"],
        "compliance_pct": compliance_pct,
        "rating":         rating,
        "pass_weight":    pass_weight,
        "total_weight":   total_weight,
        "findings":       sorted(findings, key=lambda x: (x["passed"], -x["weight"])),
        "scanned_at":     scan.data[0]["scanned_at"],
        "note": "Based on NIS2 Directive (EU) 2022/2555 Article 21 security requirements. "
                "This assessment is informational and does not constitute legal compliance certification.",
    }


# ── NIS2 Article labels for AI narrative ─────────────────────────────────────
NIS2_ARTICLE_LABELS = {
    "Art.21(2)(a)": "Security policies & risk analysis",
    "Art.21(2)(b)": "Incident handling & threat detection",
    "Art.21(2)(c)": "Business continuity & recovery",
    "Art.21(2)(d)": "Supply chain & software security",
    "Art.21(2)(e)": "Network & information system security",
    "Art.21(2)(f)": "Vulnerability handling & disclosure",
    "Art.21(2)(g)": "Cyber hygiene & data protection",
    "Art.21(2)(h)": "Cryptography & encryption",
    "Art.21(2)(i)": "Access control & authentication",
    "Art.23":       "Incident reporting obligations",
}


@app.post("/domains/{domain_id}/nis2/report")
async def generate_nis2_report(domain_id: str, authorization: str = Header(None)):
    """
    AI-generated NIS2 Compliance Autopilot report.
    Maps scan findings → NIS2 Article 21 requirements → remediation steps.
    """
    user = get_user_from_header(authorization)
    db   = get_db()

    d = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data or d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found or not your domain")
    domain_name = d.data[0]["domain"]

    scan = db.table("scans").select("checks,risk_score,scanned_at") \
        .eq("domain_id", domain_id).order("scanned_at", desc=True).limit(1).execute()
    if not scan.data:
        raise HTTPException(404, "No scan data yet — run a scan first")

    raw = scan.data[0].get("checks", []) or []
    if isinstance(raw, str):
        try: raw = json.loads(raw)
        except: raw = []

    check_map = {c.get("check"): c for c in raw}

    # Build per-article status from findings
    article_status: dict = {}
    for check_name, (article, requirement, weight) in NIS2_MAPPING.items():
        c      = check_map.get(check_name)
        status = c.get("status", "unknown") if c else "unknown"
        passed = status in ("ok", "info")
        detail = c.get("detail", "") if c else ""
        if article not in article_status:
            article_status[article] = {
                "article":     article,
                "label":       NIS2_ARTICLE_LABELS.get(article, article),
                "checks":      [],
                "pass":        0,
                "fail":        0,
            }
        article_status[article]["checks"].append({
            "check": check_name, "requirement": requirement,
            "passed": passed, "status": status, "detail": detail[:200],
        })
        if passed:
            article_status[article]["pass"] += 1
        else:
            article_status[article]["fail"] += 1

    # Add Art.23 (incident reporting) — inferred from breach/blacklist checks
    breach_checks = ["virustotal", "urlhaus", "spamhaus", "safebrowsing"]
    breach_triggered = any(
        check_map.get(c, {}).get("status") in ("critical", "warning")
        for c in breach_checks
    )
    article_status["Art.23"] = {
        "article": "Art.23",
        "label":   NIS2_ARTICLE_LABELS["Art.23"],
        "checks":  [{"check": "incident_indicators", "requirement": "Incident reporting readiness",
                     "passed": not breach_triggered,
                     "status": "warning" if breach_triggered else "ok",
                     "detail": "Active threat indicators detected — incident reporting procedures should be reviewed" if breach_triggered else "No active incident indicators detected"}],
        "pass": 0 if breach_triggered else 1,
        "fail": 1 if breach_triggered else 0,
    }

    # Build gap list for critical failures
    gaps = []
    for art, info in article_status.items():
        for chk in info["checks"]:
            if not chk["passed"] and chk["status"] in ("critical", "warning"):
                gaps.append(f"[{art}] {chk['requirement']}: {chk['status'].upper()}"
                            + (f" — {chk['detail']}" if chk['detail'] else ""))

    # Compute overall compliance score
    findings_list = []
    total_w = pass_w = 0
    for check_name, (article, requirement, weight) in NIS2_MAPPING.items():
        c      = check_map.get(check_name)
        status = c.get("status", "unknown") if c else "unknown"
        passed = status in ("ok", "info")
        total_w += weight
        if passed: pass_w += weight
        findings_list.append({"check": check_name, "article": article,
                               "requirement": requirement, "status": status,
                               "passed": passed, "weight": weight})
    compliance_pct = round(pass_w / total_w * 100) if total_w else 0
    rating = "COMPLIANT" if compliance_pct >= 80 else "PARTIAL" if compliance_pct >= 50 else "NON-COMPLIANT"

    # AI narrative
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    ai_narrative = {"executive_summary": "", "article_narratives": {}, "priority_actions": [], "audit_statement": ""}

    if api_key:
        gap_text = "\n".join(gaps[:15]) if gaps else "No critical gaps found."
        article_summary = "\n".join(
            f"{art} ({info['label']}): {info['pass']} passed, {info['fail']} failed"
            for art, info in article_status.items()
        )
        system_prompt = (
            "You are a EU NIS2 compliance specialist. Analyse a domain's security scan results "
            "and produce a structured compliance report. Be specific, actionable, and professional. "
            "Reference exact NIS2 article numbers. Use plain text, no markdown symbols."
        )
        user_prompt = (
            f"Domain: {domain_name}\n"
            f"Overall NIS2 Compliance: {compliance_pct}% ({rating})\n"
            f"Risk Score: {scan.data[0].get('risk_score', 0)}/100\n\n"
            f"Article-by-Article Status:\n{article_summary}\n\n"
            f"Key Gaps:\n{gap_text}\n\n"
            f"Generate a NIS2 Compliance Autopilot Report with these exact sections:\n\n"
            f"1. EXECUTIVE SUMMARY\n"
            f"2-3 sentences summarising overall compliance posture for {domain_name}.\n\n"
            f"2. ARTICLE-BY-ARTICLE ASSESSMENT\n"
            f"For each of the 9 NIS2 articles above, one sentence on status and what action is needed.\n\n"
            f"3. PRIORITY REMEDIATION ACTIONS\n"
            f"List exactly 5 numbered concrete remediation steps, each mapped to a NIS2 article number.\n\n"
            f"4. AUDIT READINESS STATEMENT\n"
            f"2 sentences suitable for inclusion in a compliance audit report.\n"
        )
        try:
            result = await _call_claude_async(
                api_key=api_key,
                model="claude-haiku-4-5-20251001",
                max_tokens=1200,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                metadata={"report_type": "nis2_report", "_user": user["sub"], "domain": domain_name},
            )
            full_text = result.get("content", [{}])[0].get("text", "")
            # Parse sections
            sections = {"executive_summary": "", "article_narratives": {}, "priority_actions": [], "audit_statement": ""}
            current = None
            for line in full_text.split("\n"):
                t = line.strip()
                if not t:
                    continue
                if "EXECUTIVE SUMMARY" in t.upper():
                    current = "exec"; continue
                if "ARTICLE-BY-ARTICLE" in t.upper():
                    current = "articles"; continue
                if "PRIORITY REMEDIATION" in t.upper():
                    current = "actions"; continue
                if "AUDIT READINESS" in t.upper():
                    current = "audit"; continue
                if current == "exec":
                    sections["executive_summary"] += t + " "
                elif current == "articles":
                    sections["article_narratives"][len(sections["article_narratives"])] = t
                elif current == "actions":
                    if t[0].isdigit():
                        sections["priority_actions"].append(t)
                elif current == "audit":
                    sections["audit_statement"] += t + " "
            ai_narrative = {
                "executive_summary": sections["executive_summary"].strip(),
                "article_narratives": list(sections["article_narratives"].values()),
                "priority_actions": sections["priority_actions"][:5],
                "audit_statement": sections["audit_statement"].strip(),
                "raw": full_text,
            }
        except Exception as e:
            ai_narrative["executive_summary"] = f"AI narrative unavailable: {str(e)}"

    return {
        "domain":         domain_name,
        "compliance_pct": compliance_pct,
        "rating":         rating,
        "scanned_at":     scan.data[0]["scanned_at"],
        "article_status": list(article_status.values()),
        "findings":       sorted(findings_list, key=lambda x: (x["passed"], -x["weight"])),
        "gaps_count":     len(gaps),
        "ai_narrative":   ai_narrative,
        "note": "Based on NIS2 Directive (EU) 2022/2555. Informational only — not legal compliance certification.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# SUPPLY CHAIN MONITOR  — upload vendor list, batch scan, weekly digest
# ══════════════════════════════════════════════════════════════════════════════

class SupplyChainRequest(BaseModel):
    domains: list[str]    # up to 50 vendor domains
    label:   str = ""     # e.g. "Q1 2025 Vendor Review"


@app.post("/supply-chain/scan")
async def supply_chain_scan(body: SupplyChainRequest, background_tasks: BackgroundTasks,
                             authorization: str = Header(None)):
    """
    Submit up to 50 vendor domains for batch scanning.
    Results stored and retrievable via GET /supply-chain/results.
    """
    user = get_user_from_header(authorization)
    if len(body.domains) > 50:
        raise HTTPException(400, "Maximum 50 domains per supply chain scan")

    # Check paid plan
    db = get_db()
    paid = db.table("purchases").select("id").eq("user_id", user["sub"])\
        .is_("cancelled_at", "null").not_.is_("paid_at", "null").execute()
    if not paid.data and not is_admin(user["sub"]):
        raise HTTPException(403, "Supply chain monitoring requires an active plan")

    import uuid
    batch_id = str(uuid.uuid4())
    now      = datetime.now(timezone.utc).isoformat()
    domains  = [d.strip().lower().replace("https://","").replace("http://","").split("/")[0]
                for d in body.domains if d.strip() and "." in d]

    db.table("supply_chain_batches").insert({
        "id":       batch_id,
        "user_id":  user["sub"],
        "label":    body.label or f"Batch {now[:10]}",
        "domains":  json.dumps(domains),
        "status":   "scanning",
        "created_at": now,
    }).execute()

    background_tasks.add_task(_run_supply_chain_scan, batch_id, domains, user["sub"])
    return {"batch_id": batch_id, "domains": len(domains), "status": "scanning"}


def _run_supply_chain_scan(batch_id: str, domains: list[str], user_id: str):
    if not SCANNER_AVAILABLE:
        return
    try:
        from cee_scanner.checks import scan_domain
        from threading import Thread
        db = get_db()
        results = []
        for domain in domains:
            try:
                r = scan_domain(domain)
                results.append({
                    "domain":     domain,
                    "risk_score": r["risk_score"],
                    "critical":   r["critical"],
                    "warnings":   r["warnings"],
                    "scanned_at": r["scanned_at"],
                })
            except Exception as e:
                results.append({"domain": domain, "risk_score": None, "error": str(e)})

        high_risk = [r for r in results if (r.get("risk_score") or 0) >= 50]
        db.table("supply_chain_batches").update({
            "status":     "complete",
            "results":    json.dumps(results),
            "high_risk":  len(high_risk),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", batch_id).execute()

        # Email digest if high-risk vendors found
        if high_risk:
            user_row = db.table("users").select("email,name").eq("id", user_id).execute()
            if user_row.data:
                _send_supply_chain_digest(user_row.data[0]["email"], user_row.data[0].get("name",""),
                                          high_risk, batch_id)
    except Exception as e:
        import traceback
        print(f"[supply-chain] Batch {batch_id} failed: {e}\n{traceback.format_exc()}")
        try:
            get_db().table("supply_chain_batches").update({"status": "error"}).eq("id", batch_id).execute()
        except Exception:
            pass


def _send_supply_chain_digest(to_email: str, name: str, high_risk: list, batch_id: str):
    if not RESEND_API_KEY:
        return
    rows = "".join(
        f"<tr><td style='padding:8px 12px;border-bottom:1px solid #eee;font-family:monospace'>{r['domain']}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #eee;color:{'#C0392B' if r['risk_score']>=70 else '#D4850A'};font-weight:700'>{r['risk_score']}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #eee;color:#C0392B'>{r.get('critical',0)} critical</td></tr>"
        for r in sorted(high_risk, key=lambda x: x.get("risk_score") or 0, reverse=True)
    )
    try:
        import httpx as _hx
        _hx.post("https://api.resend.com/emails", headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        }, json={
            "from":    f"SwarmHawk <{FROM_EMAIL}>",
            "to":      [to_email],
            "subject": f"⚠️ Supply Chain Alert — {len(high_risk)} high-risk vendors detected",
            "html":    f"""<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px">
<div style="border-left:3px solid #CBFF00;padding-left:16px;margin-bottom:24px">
  <strong style="font-family:monospace;font-size:16px;background:#CBFF00;padding:4px 10px">SWARMHAWK</strong>
  <p style="margin:8px 0 0;color:#555">Supply Chain Security Digest</p>
</div>
<p>Hi {name or 'there'},</p>
<p>{len(high_risk)} of your vendor domains scored HIGH RISK (≥50). Immediate review recommended.</p>
<table style="width:100%;border-collapse:collapse;font-size:13px">
  <tr style="background:#f5f5f5"><th style="padding:8px 12px;text-align:left">Domain</th>
    <th style="padding:8px 12px;text-align:left">Risk Score</th>
    <th style="padding:8px 12px;text-align:left">Findings</th></tr>
  {rows}
</table>
<p style="margin-top:24px">View full reports at <a href="{SITE_URL}">swarmhawk.com</a></p>
<hr style="border:none;border-top:1px solid #eee;margin:24px 0">
<p style="font-size:11px;color:#999">SwarmHawk Security Intelligence · swarmhawk.com</p>
</body></html>""",
        }, timeout=15)
    except Exception as e:
        print(f"[supply-chain] digest email failed: {e}")


@app.get("/supply-chain/results")
def supply_chain_results(authorization: str = Header(None)):
    """List all supply chain scan batches for the current user."""
    user = get_user_from_header(authorization)
    db   = get_db()
    rows = db.table("supply_chain_batches").select(
        "id,label,status,high_risk,created_at,completed_at,results"
    ).eq("user_id", user["sub"]).order("created_at", desc=True).limit(20).execute()

    out = []
    for r in (rows.data or []):
        results = r.get("results")
        if isinstance(results, str):
            try: results = json.loads(results)
            except: results = []
        out.append({**r, "results": results or []})
    return {"batches": out}


# ══════════════════════════════════════════════════════════════════════════════
# MSP PLAN — $200/yr for 10 domains, white-label coming
# ══════════════════════════════════════════════════════════════════════════════

class MSPCheckoutRequest(BaseModel):
    domain_ids: list[str]   # up to 10 domain IDs to cover under MSP plan


@app.post("/checkout/msp")
async def checkout_msp(body: MSPCheckoutRequest, authorization: str = Header(None)):
    """Create Stripe checkout for MSP plan — $200/yr covers 10 domains."""
    user = get_user_from_header(authorization)
    if len(body.domain_ids) > 10:
        raise HTTPException(400, "MSP plan covers up to 10 domains")

    db     = get_db()
    u_row  = db.table("users").select("email").eq("id", user["sub"]).execute()
    email  = u_row.data[0]["email"] if u_row.data else ""

    price_id = STRIPE_MSP_PRICE_ID
    if not price_id:
        # Create inline price if no env var set
        price_data = {
            "currency": "usd",
            "unit_amount": 20000,   # $200.00
            "recurring": {"interval": "year"},
        }
    else:
        price_data = None

    try:
        create_kwargs: dict = {
            "payment_method_types": ["card"],
            "mode": "subscription",
            "customer_email": email,
            "success_url": f"{FRONTEND_URL}?payment=success&plan=msp",
            "cancel_url":  f"{FRONTEND_URL}?payment=cancel",
            "metadata": {
                "user_id":    user["sub"],
                "plan":       "msp",
                "domain_ids": json.dumps(body.domain_ids),
            },
        }
        if price_id:
            create_kwargs["line_items"] = [{"price": price_id, "quantity": 1}]
        else:
            create_kwargs["line_items"] = [{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 20000,
                    "recurring": {"interval": "year"},
                    "product_data": {
                        "name": "SwarmHawk MSP Plan",
                        "description": "10 domains · monthly auto-scans · PDF reports · supply chain monitoring",
                    },
                },
                "quantity": 1,
            }]
        session = stripe.checkout.Session.create(**create_kwargs)
        return {"url": session.url}
    except stripe.error.StripeError as e:
        raise HTTPException(400, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# DEVELOPER API PRICING
# ══════════════════════════════════════════════════════════════════════════════

_API_PLAN_PRICE_IDS = {
    "api_starter": STRIPE_API_STARTER_PRICE,
    "api_growth":  STRIPE_API_GROWTH_PRICE,
    "api_pro":     STRIPE_API_PRO_PRICE,
}

_API_PLAN_AMOUNTS = {          # cents, EUR
    "api_starter": 1900,
    "api_growth":  4900,
    "api_pro":     9900,
}

_API_PLAN_NAMES = {
    "api_starter": "API Starter — 500 calls/month",
    "api_growth":  "API Growth — 2,000 calls/month",
    "api_pro":     "API Pro — 10,000 calls/month",
}


def _apply_api_plan(db, user_id: str, plan: str):
    """Set limit_per_month on all active API keys for this user."""
    limit = API_PLAN_LIMITS.get(plan, API_PLAN_LIMITS["free"])
    db.table("api_keys").update({"limit_per_month": limit})\
        .eq("user_id", user_id).eq("active", True).execute()
    print(f"[stripe] API plan applied: user={user_id} plan={plan} limit={limit}")


def _get_user_api_plan(db, user_id: str) -> dict:
    """Return the current active API plan for a user, or 'free'."""
    rows = db.table("purchases")\
        .select("plan,stripe_sub_id,paid_at")\
        .eq("user_id", user_id)\
        .in_("plan", ["api_starter", "api_growth", "api_pro"])\
        .is_("cancelled_at", "null")\
        .order("paid_at", desc=True)\
        .limit(1).execute()
    if rows.data:
        p = rows.data[0]
        return {
            "plan":    p["plan"],
            "limit":   API_PLAN_LIMITS.get(p["plan"], 10),
            "sub_id":  p.get("stripe_sub_id"),
            "paid_at": p.get("paid_at"),
        }
    return {"plan": "free", "limit": API_PLAN_LIMITS["free"], "sub_id": None, "paid_at": None}


class ApiPlanCheckoutRequest(BaseModel):
    plan: str  # "api_starter" | "api_growth" | "api_pro"


@app.post("/checkout/api-plan")
def checkout_api_plan(body: ApiPlanCheckoutRequest, authorization: str = Header(None)):
    """Create a Stripe Checkout session for an API pricing tier subscription."""
    if body.plan not in _API_PLAN_NAMES:
        raise HTTPException(400, "plan must be one of: api_starter, api_growth, api_pro")
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe not configured")

    user  = get_user_from_header(authorization)
    db    = get_db()
    u_row = db.table("users").select("email").eq("id", user["sub"]).execute()
    email = u_row.data[0]["email"] if u_row.data else ""

    price_id = _API_PLAN_PRICE_IDS.get(body.plan, "")
    if price_id:
        line_items = [{"price": price_id, "quantity": 1}]
    else:
        line_items = [{
            "price_data": {
                "currency":    "eur",
                "unit_amount": _API_PLAN_AMOUNTS[body.plan],
                "recurring":   {"interval": "month"},
                "product_data": {
                    "name":        _API_PLAN_NAMES[body.plan],
                    "description": f"{API_PLAN_LIMITS[body.plan]:,} API calls/month. Cancel anytime.",
                },
            },
            "quantity": 1,
        }]

    meta = {"user_id": str(user["sub"]), "plan": body.plan}
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=line_items,
            success_url=f"{SITE_URL}?api_upgrade=success",
            cancel_url=f"{SITE_URL}?api_upgrade=cancelled",
            metadata=meta,
            customer_email=email,
            subscription_data={"metadata": meta},
        )
        return {"url": session.url, "plan": body.plan}
    except stripe.error.StripeError as e:
        raise HTTPException(400, str(e))


@app.get("/api/v1/plan")
def get_api_plan(authorization: str = Header(None)):
    """Return the current API pricing plan and usage for the authenticated user."""
    user = get_user_from_header(authorization)
    db   = get_db()
    plan_info = _get_user_api_plan(db, user["sub"])
    # Enrich with actual usage from the user's API keys
    keys = db.table("api_keys").select("calls_this_month,limit_per_month")\
        .eq("user_id", user["sub"]).execute()
    calls = sum((k.get("calls_this_month") or 0) for k in (keys.data or []))
    plan_info["calls_this_month"] = calls
    return plan_info


# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN DEATH PREDICTOR
# Heuristic risk model → "73% chance of incident in 90 days"
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/domains/{domain_id}/death-predictor")
def domain_death_predictor(domain_id: str, authorization: str = Header(None)):
    """
    Predict probability of security incident in next 90 days.
    Model inputs: cert age, DNS age, risk trend, breach history, CVE exposure.
    """
    user = get_user_from_header(authorization)
    db   = get_db()
    d = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data or d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found or not your domain")

    scans = db.table("scans").select("risk_score,critical,warnings,checks,scanned_at")\
        .eq("domain_id", domain_id).order("scanned_at", desc=True).limit(6).execute()
    if not scans.data:
        raise HTTPException(404, "No scan data yet — run a scan first")

    latest    = scans.data[0]
    risk      = latest.get("risk_score") or 0
    criticals = latest.get("critical") or 0
    warnings  = latest.get("warnings") or 0
    raw       = latest.get("checks", []) or []
    if isinstance(raw, str):
        try: raw = json.loads(raw)
        except: raw = []
    check_map = {c.get("check"): c for c in raw}

    # Score factors (each adds to probability)
    factors = []
    prob    = 0.0

    # 1. Risk trend (worsening = higher risk)
    if len(scans.data) >= 2:
        oldest = scans.data[-1].get("risk_score") or 0
        trend  = risk - oldest
        if trend > 20:
            prob += 25; factors.append(("Risk trending up +{:.0f} pts over last {} scans".format(trend, len(scans.data)), 25))
        elif trend > 10:
            prob += 12; factors.append(("Risk trending up moderately".format(trend), 12))

    # 2. Active CVEs
    if check_map.get("cve", {}).get("status") == "critical":
        prob += 20; factors.append(("Active CVEs detected on exposed services", 20))

    # 3. Blocklist / malware
    for chk, label in [("urlhaus","URLhaus malware listing"), ("spamhaus","Spamhaus DBL listing"),
                        ("safebrowsing","Google Safe Browsing flag"), ("virustotal","VirusTotal detections")]:
        if check_map.get(chk, {}).get("status") == "critical":
            prob += 15; factors.append((label, 15))

    # 4. SSL issues
    ssl_status = check_map.get("ssl", {}).get("status", "ok")
    if ssl_status == "critical":
        prob += 18; factors.append(("SSL certificate expired or invalid", 18))
    elif ssl_status == "warning":
        prob += 8; factors.append(("SSL certificate expiring soon", 8))

    # 5. Data breach exposure
    if check_map.get("breach", {}).get("status") in ("critical", "warning"):
        prob += 12; factors.append(("Credentials found in data breaches", 12))

    # 6. High risk score baseline
    if risk >= 70:
        prob += 20; factors.append(("Overall risk score in critical range (≥70)", 20))
    elif risk >= 50:
        prob += 10; factors.append(("Overall risk score elevated (50-69)", 10))

    # 7. Port exposure
    if check_map.get("ip_intel", {}).get("status") in ("critical", "warning"):
        prob += 8; factors.append(("Risky ports or blocklisted IPs detected", 8))

    # Clamp to 95% max (never 100% certain)
    prob = min(round(prob), 95)

    # Category
    if prob >= 70:
        verdict = "VERY HIGH RISK"
        color   = "#C0392B"
        action  = "Immediate remediation required. Breach or outage highly likely within 90 days."
    elif prob >= 45:
        verdict = "ELEVATED RISK"
        color   = "#D4850A"
        action  = "Multiple unresolved vulnerabilities. Recommend addressing within 2-4 weeks."
    elif prob >= 20:
        verdict = "MODERATE RISK"
        color   = "#D4850A"
        action  = "Some exposure detected. Monitor closely and address warnings."
    else:
        verdict = "LOW RISK"
        color   = "#2ECC71"
        action  = "Domain is well-secured. Continue monitoring."

    return {
        "domain":      d.data[0]["domain"],
        "probability": prob,
        "verdict":     verdict,
        "color":       color,
        "action":      action,
        "factors":     factors,
        "horizon_days": 90,
        "model_note":  "Heuristic model based on scan findings. Not a guarantee of security outcomes.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL THREAT INTELLIGENCE MAP — aggregates Marketing scanner data
# ══════════════════════════════════════════════════════════════════════════════

_map_cache: dict = {"data": None, "built_at": None}
_MAP_CACHE_TTL = 3600  # 1 hour


def _build_map_data() -> dict:
    """Aggregate threat data per country for the threat map.

    Data sources (merged in order of priority):
    1. outreach_prospects — real scan results with CVSS scores
    2. PROSPECT_DOMAINS   — hardcoded known domains per country (domain count only)
    3. COUNTRY_TLDS       — all monitored countries shown as 'in pipeline' even if empty
    """
    from outreach import get_db as outreach_get_db, PROSPECT_DOMAINS, COUNTRY_TLDS
    db = outreach_get_db()

    # ── Base layer: all known countries from PROSPECT_DOMAINS + COUNTRY_TLDS ──
    country_data: dict = {}

    # Seed every country we monitor so the map is never blank
    for cc in COUNTRY_TLDS:
        country_data[cc] = {
            "country":           cc,
            "domains":           0,
            "scanned":           0,
            "avg_risk":          0,
            "high_risk_domains": 0,
            "critical_findings": 0,
            "_cvss_sum":         0.0,
            "_cvss_count":       0,
        }

    # Add domain counts from PROSPECT_DOMAINS hardcoded list
    for cc, domains in PROSPECT_DOMAINS.items():
        cc = cc.upper()
        if cc not in country_data:
            country_data[cc] = {
                "country": cc, "domains": 0, "scanned": 0,
                "avg_risk": 0, "high_risk_domains": 0, "critical_findings": 0,
                "_cvss_sum": 0.0, "_cvss_count": 0,
            }
        country_data[cc]["domains"] = max(country_data[cc]["domains"], len(domains))

    # ── Overlay: real scan results from outreach_prospects ─────────────────────
    try:
        rows = db.table("outreach_prospects")\
            .select("domain,country,max_cvss,scanned_at")\
            .execute()

        scan_counts: dict = {}  # cc -> {domains, scanned, cvss_list}
        for r in (rows.data or []):
            cc = (r.get("country") or "").upper().strip()
            if not cc or cc in ("EU", "??", ""):
                cc = tld_to_country(r.get("domain", "unknown.com"))
            if not cc:
                continue
            if cc not in scan_counts:
                scan_counts[cc] = {"domains": 0, "scanned": 0, "cvss": []}
            scan_counts[cc]["domains"] += 1
            if r.get("scanned_at"):
                scan_counts[cc]["scanned"] += 1
            if r.get("max_cvss") is not None:
                try:
                    scan_counts[cc]["cvss"].append(float(r["max_cvss"]))
                except (ValueError, TypeError):
                    pass

        for cc, sc in scan_counts.items():
            if cc not in country_data:
                country_data[cc] = {
                    "country": cc, "domains": 0, "scanned": 0,
                    "avg_risk": 0, "high_risk_domains": 0, "critical_findings": 0,
                    "_cvss_sum": 0.0, "_cvss_count": 0,
                }
            # Real scan data overrides domain count
            country_data[cc]["domains"]  = max(country_data[cc]["domains"], sc["domains"])
            country_data[cc]["scanned"]  = sc["scanned"]
            if sc["cvss"]:
                avg_cvss = sum(sc["cvss"]) / len(sc["cvss"])
                country_data[cc]["avg_risk"]          = round(avg_cvss * 10, 1)
                country_data[cc]["high_risk_domains"] = sum(1 for s in sc["cvss"] if s >= 7.0)
                country_data[cc]["critical_findings"] = sum(1 for s in sc["cvss"] if s >= 9.0)

    except Exception as e:
        print(f"[map] outreach_prospects query failed: {e}")

    # ── Overlay: real scan risk_scores from user scans table ───────────────────
    try:
        admin_db = get_admin_db()
        user_domains = admin_db.table("domains").select("id,domain,country").execute()
        dom_map: dict = {}  # domain_id -> (domain, country_code)
        for ud in (user_domains.data or []):
            d   = ud.get("domain", "")
            cc  = (ud.get("country") or "").upper().strip()
            if not cc or cc in ("EU", "??", ""):
                cc = tld_to_country(d)
            dom_map[ud["id"]] = (d, cc)

        if dom_map:
            scans_res = admin_db.table("scans")\
                .select("domain_id,risk_score,scanned_at")\
                .order("scanned_at", desc=True)\
                .limit(2000)\
                .execute()
            seen_scan: set = set()
            for s in (scans_res.data or []):
                did = s.get("domain_id")
                if did not in dom_map or did in seen_scan:
                    continue
                seen_scan.add(did)
                _, cc = dom_map[did]
                score = s.get("risk_score") or 0
                if cc not in country_data:
                    country_data[cc] = {
                        "country": cc, "domains": 0, "scanned": 0,
                        "avg_risk": 0, "high_risk_domains": 0, "critical_findings": 0,
                        "_cvss_sum": 0.0, "_cvss_count": 0,
                    }
                country_data[cc]["domains"] = max(country_data[cc].get("domains", 0) + 1, 1)
                country_data[cc]["scanned"] = country_data[cc].get("scanned", 0) + 1
                country_data[cc]["_cvss_sum"]   = country_data[cc].get("_cvss_sum", 0) + score
                country_data[cc]["_cvss_count"] = country_data[cc].get("_cvss_count", 0) + 1
                if score >= 70:
                    country_data[cc]["high_risk_domains"] = country_data[cc].get("high_risk_domains", 0) + 1

        # Recalculate avg_risk for countries that got scan data
        for cc, row in country_data.items():
            if row.get("_cvss_count", 0) > 0:
                row["avg_risk"] = round(row["_cvss_sum"] / row["_cvss_count"], 1)

    except Exception as e:
        print(f"[map] scans table overlay failed: {e}")

    # Strip internal keys, drop countries with 0 domains
    result = []
    for cc, row in country_data.items():
        row.pop("_cvss_sum", None)
        row.pop("_cvss_count", None)
        if row["domains"] > 0 or cc in PROSPECT_DOMAINS or cc in COUNTRY_TLDS:
            # Ensure in-pipeline countries with 0 scanned show at least domain=1
            if row["domains"] == 0:
                row["domains"] = len(PROSPECT_DOMAINS.get(cc, [])) or 1
            result.append(row)

    now = datetime.now(timezone.utc).isoformat()
    return {
        "countries":     sorted(result, key=lambda x: (x["avg_risk"], x["scanned"]), reverse=True),
        "total_domains": sum(r["domains"] for r in result),
        "total_scanned": sum(r["scanned"] for r in result),
        "generated_at":  now,
    }


@app.get("/check-domains-available")
def check_domains_available(domains: str):
    """
    Public: check whether domains are registered via RDAP.
    Pass comma-separated list, max 10. Returns {domain: 'available'|'taken'|'unknown'}.
    """
    import concurrent.futures
    domain_list = [d.strip().lower() for d in domains.split(',') if d.strip()][:10]

    def check_one(d):
        try:
            r = requests.get(f"https://rdap.org/domain/{d}", timeout=6, allow_redirects=True,
                             headers={"Accept": "application/json"})
            if r.status_code == 200:
                return d, "taken"
            elif r.status_code in (404, 400):
                return d, "available"
            else:
                return d, "unknown"
        except Exception:
            return d, "unknown"

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for domain, status in ex.map(check_one, domain_list):
            results[domain] = status
    return results


@app.get("/map/data")
def attack_map_data():
    """
    Public endpoint: aggregated threat data per country from Marketing scanner.
    No auth required. Cached for 1 hour.
    """
    global _map_cache
    now = datetime.now(timezone.utc)
    built_at = _map_cache.get("built_at")
    if _map_cache["data"] is None or built_at is None or \
            (now - built_at).total_seconds() > _MAP_CACHE_TTL:
        try:
            _map_cache["data"]     = _build_map_data()
            _map_cache["built_at"] = now
        except Exception as e:
            return {"countries": [], "error": str(e)}
    return _map_cache["data"]


@app.get("/map/country/{code}")
def map_country_top_domains(code: str):
    """
    Public: top 100 highest-risk scanned domains for a country.
    Matches by country column OR by domain TLD (same fallback as _build_map_data).
    Also pulls real risk_score from user scans table.
    No auth required.
    """
    code = code.upper()
    seen: set = set()
    domain_rows: list = []

    def fmt_date(raw):
        if not raw:
            return ""
        try:
            from datetime import datetime as _dt
            dt = _dt.fromisoformat(str(raw).replace("Z", "+00:00"))
            return dt.strftime("%d %b %Y")
        except Exception:
            return str(raw)[:10]

    try:
        from outreach import get_db as outreach_get_db
        db = outreach_get_db()

        # ── 1. Outreach prospects — fetch ALL scanned rows, filter by country/TLD ──
        all_prospects = db.table("outreach_prospects")\
            .select("domain,country,max_cvss,scanned_at")\
            .not_.is_("scanned_at", "null")\
            .execute()

        for r in (all_prospects.data or []):
            dom = r.get("domain", "")
            cc = (r.get("country") or "").upper().strip()
            if not cc or cc in ("EU", "??", ""):
                cc = tld_to_country(dom)
            if cc != code:
                continue
            if dom in seen:
                continue
            seen.add(dom)
            cvss = r.get("max_cvss") or 0
            risk_score = min(100, int(round(cvss * 10)))
            domain_rows.append({
                "domain": dom,
                "risk_score": risk_score,
                "scanned_at": fmt_date(r.get("scanned_at")),
                "max_cvss": round(cvss, 1),
                "source": "outreach",
            })

        # ── 2. User-scanned domains — domains + latest scan risk_score ──
        try:
            admin_db = get_admin_db()
            user_domains = admin_db.table("domains")\
                .select("id,domain,country")\
                .execute()
            dom_ids = []
            dom_map = {}
            for ud in (user_domains.data or []):
                d = ud.get("domain", "")
                cc = (ud.get("country") or "").upper().strip()
                if not cc or cc in ("EU", "??", ""):
                    cc = tld_to_country(d)
                if cc != code:
                    continue
                dom_ids.append(ud["id"])
                dom_map[ud["id"]] = d

            if dom_ids:
                # Fetch latest scan per domain
                scans_res = admin_db.table("scans")\
                    .select("domain_id,risk_score,scanned_at")\
                    .in_("domain_id", dom_ids[:50])\
                    .order("scanned_at", desc=True)\
                    .execute()
                seen_scan: set = set()
                for s in (scans_res.data or []):
                    did = s.get("domain_id")
                    if did in seen_scan:
                        continue
                    seen_scan.add(did)
                    dom = dom_map.get(did, "")
                    if not dom or dom in seen:
                        continue
                    seen.add(dom)
                    domain_rows.append({
                        "domain": dom,
                        "risk_score": s.get("risk_score") or 0,
                        "scanned_at": fmt_date(s.get("scanned_at")),
                        "max_cvss": 0,
                        "source": "scan",
                    })
        except Exception:
            pass  # scans table optional — outreach data is enough

        # Sort by risk_score desc, limit 100
        domain_rows.sort(key=lambda x: x["risk_score"], reverse=True)
        domain_rows = domain_rows[:100]

        scanned_count = len(domain_rows)
        high_risk = sum(1 for d in domain_rows if d["risk_score"] >= 70)
        avg_risk = int(sum(d["risk_score"] for d in domain_rows) / scanned_count) if scanned_count else 0
        summary = {
            "total_tracked": scanned_count,
            "scanned": scanned_count,
            "avg_risk": avg_risk,
            "high_risk": high_risk,
        }

    except Exception as exc:
        summary = {"error": str(exc)}

    return {"country": code, "domains": domain_rows, "total": len(domain_rows), "summary": summary}


# ══════════════════════════════════════════════════════════════════════════════
# PARANOIDLAB — dark-web leak & credential intelligence
# API docs: https://paranoidlab.com/v1/docs
# ══════════════════════════════════════════════════════════════════════════════

PARANOIDLAB_BASE = "https://paranoidlab.com/v1"


def _pl_headers() -> dict:
    return {"X-Key": PARANOIDLAB_API_KEY, "Content-Type": "application/json"}


def paranoidlab_search(domain: str) -> dict:
    """
    Quick public search (no auth required).
    Returns aggregated leak counts for a domain.
    """
    try:
        resp = requests.post(
            f"{PARANOIDLAB_BASE}/search",
            json={"query": domain},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"[paranoidlab] search error: {e}")
    return {}


def paranoidlab_leaks(domain: str, limit: int = 20) -> dict:
    """
    Fetch paginated leaks for a domain target using API key.
    Returns {"total": int, "items": [...], "types": {...}}
    """
    if not PARANOIDLAB_API_KEY:
        return {"error": "No ParanoidLab API key configured"}
    try:
        resp = requests.get(
            f"{PARANOIDLAB_BASE}/leaks",
            headers=_pl_headers(),
            params={"data_url": domain, "limit": limit, "offset": 0},
            timeout=15,
        )
        if resp.status_code == 200:
            data  = resp.json()
            items = data.get("items") or data.get("leaks") or []
            # Aggregate by type
            types: dict = {}
            for item in items:
                t = item.get("type", "unknown")
                types[t] = types.get(t, 0) + 1
            return {
                "total": data.get("total") or len(items),
                "items": items[:10],   # cap detail rows
                "types": types,
            }
        elif resp.status_code == 401:
            return {"error": "Invalid ParanoidLab API key"}
        else:
            return {"error": f"ParanoidLab API error {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def paranoidlab_telegram(domain: str, limit: int = 20) -> dict:
    """Search Telegram dark-web posts mentioning the domain."""
    if not PARANOIDLAB_API_KEY:
        return {"error": "No ParanoidLab API key configured"}
    try:
        resp = requests.get(
            f"{PARANOIDLAB_BASE}/telegram/posts",
            headers=_pl_headers(),
            params={"keyword": domain, "limit": limit},
            timeout=15,
        )
        if resp.status_code == 200:
            data  = resp.json()
            posts = data.get("posts") or data.get("items") or []
            return {
                "total":   data.get("total") or len(posts),
                "posts":   posts[:5],
                "next":    data.get("next"),
            }
        return {"error": f"Telegram API {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def paranoidlab_create_target(domain: str) -> dict:
    """Register a domain as a ParanoidLab monitoring target."""
    if not PARANOIDLAB_API_KEY:
        return {"error": "No ParanoidLab API key configured"}
    try:
        resp = requests.post(
            f"{PARANOIDLAB_BASE}/targets/create",
            headers=_pl_headers(),
            json={"type": "domain", "value": domain, "tag": "swarmhawk"},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            return resp.json()
        return {"error": f"Create target failed: {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def paranoidlab_get_targets(domain: str) -> list:
    """Return existing ParanoidLab targets matching the domain."""
    if not PARANOIDLAB_API_KEY:
        return []
    try:
        resp = requests.get(
            f"{PARANOIDLAB_BASE}/targets",
            headers=_pl_headers(),
            params={"type": "domain", "search": domain, "limit": 5},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("items") or data.get("targets") or []
    except Exception as e:
        print(f"[paranoidlab] targets error: {e}")
    return []


# ── Risk scoring helper ───────────────────────────────────────────────────────
def _pl_risk(total: int, types: dict) -> tuple[str, str]:
    """Return (status, summary) based on leak counts."""
    passwords = types.get("password", 0)
    cookies   = types.get("cookie", 0)
    pii       = types.get("pii", 0)
    if total == 0:
        return "ok", "No leaked credentials or PII found in dark-web sources"
    if passwords >= 10 or pii >= 5 or total >= 25:
        return "critical", f"{total} leaked records found — {passwords} passwords, {cookies} cookies, {pii} PII records"
    if total > 0:
        return "warning", f"{total} leaked records detected — {passwords} passwords, {cookies} cookies, {pii} PII records"
    return "ok", "No significant leaks detected"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/domains/{domain_id}/paranoidlab")
async def paranoidlab_domain_summary(domain_id: str, authorization: str = Header(None)):
    """
    ParanoidLab dark-web intelligence summary for a domain.
    Returns leak counts + Telegram mentions.
    """
    user = get_user_from_header(authorization)
    db   = get_db()
    d    = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data or d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found")
    domain = d.data[0]["domain"]

    # Run searches in parallel-ish (sequential but fast enough)
    search_data  = paranoidlab_search(domain)
    leaks_data   = paranoidlab_leaks(domain, limit=20)
    telegram_data = paranoidlab_telegram(domain, limit=10)

    total = leaks_data.get("total", 0)
    types = leaks_data.get("types", {})
    status, summary = _pl_risk(total, types)

    return {
        "domain":       domain,
        "status":       status,
        "summary":      summary,
        "total_leaks":  total,
        "leak_types":   types,
        "leak_items":   leaks_data.get("items", []),
        "telegram":     telegram_data,
        "search_raw":   search_data,
        "error":        leaks_data.get("error") or telegram_data.get("error"),
        "powered_by":   "paranoidlab.com",
    }


@app.post("/domains/{domain_id}/paranoidlab/fetch")
async def paranoidlab_fetch_leaks(domain_id: str, authorization: str = Header(None)):
    """
    Register domain as a ParanoidLab target and trigger a full leak fetch.
    Costs 1 credit per unique source checked.
    """
    user = get_user_from_header(authorization)
    db   = get_db()
    d    = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data or d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found")

    if not PARANOIDLAB_API_KEY:
        raise HTTPException(503, "ParanoidLab API key not configured")

    domain = d.data[0]["domain"]

    # Find or create target
    targets = paranoidlab_get_targets(domain)
    if targets:
        target_id = targets[0]["id"]
    else:
        created = paranoidlab_create_target(domain)
        if "error" in created:
            raise HTTPException(502, f"Could not register target: {created['error']}")
        target_id = created.get("id") or created.get("target", {}).get("id")

    if not target_id:
        raise HTTPException(502, "Failed to get target ID from ParanoidLab")

    # Trigger fetch (costs credits)
    try:
        resp = requests.post(
            f"{PARANOIDLAB_BASE}/leaks/fetch",
            headers=_pl_headers(),
            json={"target_id": target_id, "leak_types": ["password", "cookie", "pii"], "notify": False},
            timeout=15,
        )
        if resp.status_code == 200:
            result = resp.json()
            return {
                "domain":     domain,
                "target_id":  target_id,
                "request_id": result.get("request_id"),
                "status":     result.get("status"),
                "cost":       result.get("cost"),
            }
        raise HTTPException(502, f"Fetch failed: {resp.status_code} {resp.text[:200]}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, str(e))


@app.get("/domains/{domain_id}/paranoidlab/requests")
async def paranoidlab_fetch_status(domain_id: str, authorization: str = Header(None)):
    """Check status of pending ParanoidLab leak fetch requests for a domain."""
    user = get_user_from_header(authorization)
    db   = get_db()
    d    = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data or d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found")

    if not PARANOIDLAB_API_KEY:
        raise HTTPException(503, "ParanoidLab API key not configured")

    domain = d.data[0]["domain"]
    try:
        resp = requests.get(
            f"{PARANOIDLAB_BASE}/leaks/requests",
            headers=_pl_headers(),
            params={"target": domain, "limit": 10},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        raise HTTPException(502, f"Error {resp.status_code}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, str(e))


# ── Also expose a /paranoidlab/search endpoint for quick public lookup ────────
@app.post("/paranoidlab/search")
async def pl_public_search(body: dict):
    """Quick no-auth domain search via ParanoidLab public search endpoint."""
    query = (body.get("query") or "").strip()
    if not query or "." not in query:
        raise HTTPException(400, "Invalid query")
    data = paranoidlab_search(query)
    return data


# ══════════════════════════════════════════════════════════════════════════════
# COMPETITOR INTELLIGENCE — track competitor domains with weekly diff
# ══════════════════════════════════════════════════════════════════════════════

class CompetitorRequest(BaseModel):
    domain: str
    label:  str = ""

@app.post("/competitors")
def add_competitor(body: CompetitorRequest, background_tasks: BackgroundTasks,
                    authorization: str = Header(None)):
    """Add a competitor domain to track. Scanned weekly with diff alerts."""
    user   = get_user_from_header(authorization)
    domain = body.domain.strip().lower().replace("https://","").replace("http://","").split("/")[0]
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")

    db = get_db()
    existing = db.table("competitors").select("id").eq("user_id", user["sub"])\
        .eq("domain", domain).execute()
    if existing.data:
        raise HTTPException(409, "Already tracking this competitor")

    # Max 5 competitors per user (free), 20 paid
    count = db.table("competitors").select("id", count="exact").eq("user_id", user["sub"]).execute()
    paid  = db.table("purchases").select("id").eq("user_id", user["sub"])\
        .is_("cancelled_at", "null").not_.is_("paid_at", "null").execute()
    limit = 20 if paid.data else 5
    if (count.count or 0) >= limit:
        raise HTTPException(403, f"Competitor limit reached ({limit}). Upgrade for more.")

    import uuid
    cid = str(uuid.uuid4())
    db.table("competitors").insert({
        "id":         cid,
        "user_id":    user["sub"],
        "domain":     domain,
        "label":      body.label or domain,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

    # Trigger first scan immediately
    background_tasks.add_task(_scan_competitor, cid, domain)
    return {"id": cid, "domain": domain, "status": "scanning"}


@app.get("/competitors")
def list_competitors(authorization: str = Header(None)):
    """List tracked competitor domains with latest scan data."""
    user = get_user_from_header(authorization)
    db   = get_db()
    rows = db.table("competitors").select("*").eq("user_id", user["sub"])\
        .order("created_at", desc=True).execute()

    out = []
    for c in (rows.data or []):
        # Get last 2 scans for diff
        scans = db.table("competitor_scans").select("risk_score,critical,warnings,scanned_at")\
            .eq("competitor_id", c["id"]).order("scanned_at", desc=True).limit(2).execute()
        latest = scans.data[0] if scans.data else None
        prev   = scans.data[1] if len(scans.data) > 1 else None
        out.append({
            **c,
            "risk_score":   latest["risk_score"] if latest else None,
            "critical":     latest["critical"]   if latest else None,
            "warnings":     latest["warnings"]   if latest else None,
            "scanned_at":   latest["scanned_at"] if latest else None,
            "prev_score":   prev["risk_score"]   if prev   else None,
            "score_delta":  ((latest["risk_score"] or 0) - (prev["risk_score"] or 0)) if (latest and prev) else None,
        })
    return {"competitors": out}


@app.delete("/competitors/{competitor_id}")
def remove_competitor(competitor_id: str, authorization: str = Header(None)):
    user = get_user_from_header(authorization)
    db   = get_db()
    db.table("competitors").delete().eq("id", competitor_id).eq("user_id", user["sub"]).execute()
    return {"deleted": competitor_id}


def _scan_competitor(competitor_id: str, domain: str):
    """Scan a competitor domain and store the result."""
    if not SCANNER_AVAILABLE:
        return
    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)
        db = get_db()
        import uuid
        db.table("competitor_scans").insert({
            "id":            str(uuid.uuid4()),
            "competitor_id": competitor_id,
            "risk_score":    result["risk_score"],
            "critical":      result["critical"],
            "warnings":      result["warnings"],
            "checks":        result["checks"],
            "scanned_at":    result["scanned_at"],
        }).execute()
        print(f"[competitor] Scanned {domain}: score={result['risk_score']}")
    except Exception as e:
        print(f"[competitor] Scan failed for {domain}: {e}")


@app.get("/competitors/{competitor_id}/history")
def competitor_history(competitor_id: str, authorization: str = Header(None)):
    """Return scan history for a competitor domain."""
    user = get_user_from_header(authorization)
    db   = get_db()
    # Verify ownership
    c = db.table("competitors").select("id,user_id,domain,label").eq("id", competitor_id).execute()
    if not c.data or c.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found")
    scans = db.table("competitor_scans").select("risk_score,critical,warnings,scanned_at")\
        .eq("competitor_id", competitor_id).order("scanned_at", desc=True).limit(52).execute()
    return {"competitor": c.data[0], "history": scans.data or []}
