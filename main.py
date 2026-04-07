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
import asyncio
import httpx
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks, Query, APIRouter, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
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
PORTKEY_API_KEY      = os.getenv("PORTKEY_API_KEY", "")                 # Portkey AI gateway key
PORTKEY_WORKSPACE    = os.getenv("PORTKEY_WORKSPACE_SLUG", "")          # Portkey workspace slug
PARANOIDLAB_API_KEY = os.getenv("PARANOIDLAB_API_KEY", "")              # paranoidlab.com leak intel
SHODAN_API_KEY      = os.getenv("SHODAN_API_KEY", "")                   # shodan.io attack surface intel
RESEND_API_KEY      = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL          = os.getenv("OUTREACH_FROM", "hello@swarmhawk.com")       # verified Resend domain
REPORT_FROM_EMAIL   = os.getenv("REPORT_FROM_EMAIL", "reports@swarmhawk.com") # user-facing reports
GOOGLE_CLIENT_ID    = os.getenv("GOOGLE_CLIENT_ID", "")
SITE_URL            = os.getenv("SITE_URL", "https://www.swarmhawk.com")
API_URL             = os.getenv("API_URL", "https://swarmhawk-backend.onrender.com")

# ── Stripe — lazy import to avoid 4-5s startup cost ─────────────────────────
_stripe = None
def _get_stripe():
    global _stripe
    if _stripe is None:
        import stripe as _s
        _s.api_key = STRIPE_SECRET_KEY
        _stripe = _s
    return _stripe

# ── Supabase clients ──────────────────────────────────────────────────────────

db: Client = None
admin_db: Client = None

def get_db() -> Client:
    """Return a service-role Supabase client.
    All backend queries run with service-role key so they work correctly
    after RLS is enabled on all tables (deny-all for anon key).
    Security is enforced at the application layer via user_id filters."""
    return get_admin_db()

def get_admin_db() -> Client:
    """Return a Supabase client using the service_role key to bypass RLS.

    The client is cached as a singleton for performance, but is discarded
    and recreated whenever an SSL/connection error is detected so that a
    dropped Supabase connection (idle timeout, server restart, free-tier
    pause) is transparently healed on the next request.
    """
    global admin_db
    key = SUPABASE_SERVICE_KEY or SUPABASE_KEY
    if not SUPABASE_URL or not key:
        raise HTTPException(503, "Database not configured — set SUPABASE_URL and SUPABASE_KEY on Render")
    if admin_db is None:
        try:
            admin_db = create_client(SUPABASE_URL, key)
        except Exception as e:
            raise HTTPException(503, f"Database connection failed: {str(e)[:200]}")
    return admin_db


_SSL_KEYWORDS = ("eof", "ssl", "broken pipe", "connection reset", "connection refused", "timed out")

def _reset_db_on_ssl_error(e: Exception) -> None:
    """If the exception looks like a dropped SSL/socket connection, discard
    the cached client so the next call to get_admin_db() reconnects."""
    global admin_db
    msg = str(e).lower()
    if any(kw in msg for kw in _SSL_KEYWORDS):
        admin_db = None

def _reset_db_on_ssl_error_msg(detail: str) -> None:
    """Same as above but takes a plain string (used in the global HTTP exception handler
    where we only have the HTTPException detail, not the original exception object)."""
    global admin_db
    msg = detail.lower()
    if any(kw in msg for kw in _SSL_KEYWORDS):
        admin_db = None

# ── App ───────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager

from integrations import CONNECTORS, CONNECTOR_META, STIXConnector, fire_integrations_sync

# ── SSE alert bus (thread-safe: pipeline workers → async SSE clients) ─────────
_sse_listeners: list[asyncio.Queue] = []

def _notify_sse_clients(event: dict) -> None:
    """Push an alert event to all connected SSE clients (thread-safe).

    Called from pipeline worker threads via pipeline.register_alert_callback().
    Uses loop.call_soon_threadsafe so asyncio queues are safe to write from threads.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            snapshot = _sse_listeners[:]
            for q in snapshot:
                loop.call_soon_threadsafe(q.put_nowait, event)
    except Exception:
        pass

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
    # Wire up SSE alert callback so pipeline workers can push to dashboard clients
    try:
        from pipeline import register_alert_callback
        register_alert_callback(_notify_sse_clients)
        print("✓ SSE alert callback registered")
    except Exception as e:
        print(f"SSE callback init failed: {e}")

    # Preload CISA KEV cache on startup (avoids first-scan latency)
    try:
        from intel_feeds import refresh_intel_feeds
        import threading as _threading
        _threading.Thread(target=refresh_intel_feeds, daemon=True, name="kev-preload").start()
        print("✓ KEV/EPSS preload started in background")
    except Exception as e:
        print(f"KEV preload failed: {e}")

    # Certstream worker — real-time CT log streaming
    try:
        from intel_feeds import start_certstream_worker, CERTSTREAM_ENABLED
        if CERTSTREAM_ENABLED:
            from pipeline import ingest_domains
            start_certstream_worker(ingest_fn=ingest_domains)
            print("✓ Certstream real-time CT worker started")
        else:
            print("↷ Certstream disabled (CERTSTREAM_ENABLED=false)")
    except Exception as e:
        print(f"Certstream worker init failed: {e}")

    # Global domain discovery pipeline
    # Skip if PIPELINE_WORKER_ENABLED=true — scheduling is handled by pipeline_worker.py
    if os.getenv("PIPELINE_WORKER_ENABLED", "").lower() not in ("1", "true", "yes"):
        try:
            from apscheduler.schedulers.background import BackgroundScheduler as _BGS3
            from pipeline import run_discovery_job, run_pipeline_daily, run_enrichment_weekly, run_bulk_discovery_job, run_kev_refresh_job
            _pipeline_scheduler = _BGS3(timezone="Europe/Prague")
            # Daily: Radar + CT logs + Majestic at 01:00
            _pipeline_scheduler.add_job(run_discovery_job,      "cron", hour=1,  minute=0,  id="pipeline_discovery")
            # Every 30 minutes: Tier 1 batch scan (configurable via PIPELINE_TIER1_INTERVAL_MINUTES, default 30)
            # next_run_time=datetime.now(timezone.utc) fires the first run immediately on startup
            # instead of waiting a full interval — critical after Render cold starts.
            _tier1_interval = int(os.getenv("PIPELINE_TIER1_INTERVAL_MINUTES", "30"))
            _pipeline_scheduler.add_job(run_pipeline_daily, "interval", minutes=_tier1_interval,
                                        id="pipeline_tier1", next_run_time=datetime.now(timezone.utc))
            # Weekly Sunday: full 22-check Tier 2 enrichment
            _pipeline_scheduler.add_job(run_enrichment_weekly,  "cron", day_of_week="sun",  hour=3,  minute=0,  id="pipeline_tier2")
            # Weekly Saturday: bulk discovery — Tranco + Umbrella (~2M domains)
            _pipeline_scheduler.add_job(run_bulk_discovery_job, "cron", day_of_week="sat",  hour=0,  minute=0,  id="pipeline_bulk_discovery")
            # Daily: CISA KEV refresh + immediate re-scoring of affected domains
            _pipeline_scheduler.add_job(run_kev_refresh_job,    "cron", hour=6,  minute=0,  id="kev_refresh")
            _pipeline_scheduler.start()
            print(f"✓ Pipeline scheduler started (Tier1 every {_tier1_interval}min, daily discovery 01:00, Tier2 Sun 03:00, bulk Sat 00:00, KEV refresh 06:00)")
        except Exception as e:
            print(f"Pipeline scheduler init failed: {e}")
    else:
        print("↷ Pipeline scheduler skipped — PIPELINE_WORKER_ENABLED is set (handled by worker process)")
    yield

app = FastAPI(
    title="SwarmHawk API",
    version="2.1.0",
    lifespan=lifespan,
    docs_url=None,   # disable built-in Swagger UI — served at swarmhawk.com/docs.html
    redoc_url=None,  # disable ReDoc
)

# CORS must be added BEFORE any exception handlers or routers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Global 503 handler: if the detail contains an SSL/EOF error string, reset
    the cached Supabase client so the *next* request reconnects cleanly."""
    from fastapi.responses import JSONResponse
    if exc.status_code == 503 and exc.detail:
        _reset_db_on_ssl_error_msg(str(exc.detail))
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/docs", include_in_schema=False)
async def redirect_docs():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="https://www.swarmhawk.com/docs.html", status_code=301)

@app.get("/redoc", include_in_schema=False)
async def redirect_redoc():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="https://www.swarmhawk.com/docs.html", status_code=301)

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
    domain_id: str | None = None  # required for scan/one_time; optional for professional (account-level)
    domain: str | None = None
    plan: str = "scan"  # "scan" ($5/scan) | "professional" ($588/yr) | legacy: "one_time" | "annual"

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


def send_account_deletion_email(to_email: str, name: str):
    """Send an account-deleted confirmation + re-registration link to the user."""
    if not RESEND_API_KEY:
        print(f"[auth] RESEND_API_KEY not set — skipping deletion email to {to_email}")
        return
    signup_url = f"{SITE_URL}/new/"
    display_name = name or to_email.split("@")[0]
    html = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#0e0d12;font-family:Arial,sans-serif">
<div style="max-width:580px;margin:0 auto;padding:48px 24px">

  <!-- Logo -->
  <div style="margin-bottom:32px">
    <span style="font-family:monospace;font-size:20px;font-weight:700;color:#cbff00;letter-spacing:1px">&#9679;SWARMHAWK</span>
  </div>

  <!-- Headline -->
  <h1 style="color:#f0eef8;font-size:22px;font-weight:700;margin:0 0 8px">Your account has been deleted</h1>
  <p style="color:#6b6880;font-size:14px;line-height:1.6;margin:0 0 24px">
    Hi {display_name}, this email confirms that your SwarmHawk account and all associated data
    (domains, scan reports, contacts) have been permanently removed.
  </p>

  <!-- Info box -->
  <div style="background:#16151e;border-radius:8px;padding:20px;margin-bottom:32px;border-left:3px solid #cbff00">
    <p style="color:#a0a0b8;font-size:13px;line-height:1.7;margin:0">
      <strong style="color:#f0eef8">What was deleted:</strong><br>
      Your login credentials &amp; profile &nbsp;·&nbsp; All monitored domains &nbsp;·&nbsp;
      All scan reports &amp; risk scores &nbsp;·&nbsp; All contacts &amp; outreach data
    </p>
  </div>

  <!-- Re-register CTA -->
  <p style="color:#6b6880;font-size:14px;line-height:1.6;margin:0 0 20px">
    Changed your mind? You can create a new SwarmHawk account at any time using the same email address.
  </p>
  <div style="margin-bottom:40px">
    <a href="{signup_url}"
       style="display:inline-block;background:#cbff00;color:#0e0d12;font-family:monospace;font-weight:700;font-size:13px;letter-spacing:1px;padding:14px 32px;border-radius:6px;text-decoration:none">
      CREATE NEW ACCOUNT →
    </a>
  </div>

  <!-- Divider -->
  <div style="border-top:1px solid rgba(255,255,255,.08);margin-bottom:24px"></div>

  <!-- Footer -->
  <p style="color:#3a3840;font-size:11px;margin:0;font-family:monospace;line-height:1.8">
    SwarmHawk · European Cybersecurity Intelligence<br>
    hello@swarmhawk.com · swarmhawk.com<br>
    You received this because your account was deleted.
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
                "subject": "Your SwarmHawk account has been deleted",
                "html":    html,
            },
            timeout=10,
        )
        print(f"[auth] Deletion email sent to {to_email} (status {r.status_code})")
    except Exception as e:
        print(f"[auth] Failed to send deletion email to {to_email}: {e}")


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
    return {"status": "ok", "version": "2.1.0", "scanner": SCANNER_AVAILABLE}



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
    if user.get("deleted_at"):
        raise HTTPException(403, "This account has been deleted. Use the link in your deletion confirmation email to create a new account.")
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
        if user.get("deleted_at"):
            raise HTTPException(403, "This account has been deleted. Use the link in your deletion confirmation email to create a new account.")
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

    # 1. Fetch paginated users (include deleted_at for soft-delete display)
    offset = (page - 1) * per_page
    users_res = db.table("users").select("id,email,name,auth_type,created_at,last_login,deleted_at") \
        .order("created_at", desc=True).range(offset, offset + per_page - 1).execute()
    total_res = db.table("users").select("id", count="exact").execute()

    user_ids = [u["id"] for u in (users_res.data or [])]
    if not user_ids:
        return {"users": [], "total": total_res.count or 0, "page": page, "per_page": per_page}

    # 2. Fetch domain counts for these users in one query (include deleted users' domains)
    domains_res = db.table("domains").select("user_id").in_("user_id", user_ids).execute()
    domain_counts: dict = {}
    for d in (domains_res.data or []):
        uid = d["user_id"]
        domain_counts[uid] = domain_counts.get(uid, 0) + 1

    # 3. Fetch purchase info in one query (for paid_domains count + plan detection)
    paid_res = db.table("purchases").select("user_id,plan").in_("user_id", user_ids).execute()
    paid_counts: dict = {}
    user_plans: dict = {}
    for p in (paid_res.data or []):
        uid  = p["user_id"]
        plan = p.get("plan") or ""
        paid_counts[uid] = paid_counts.get(uid, 0) + 1
        # Highest plan wins: platform > professional > annual > one_time
        existing = user_plans.get(uid, "free")
        priority = {"platform": 4, "professional": 3, "annual": 2, "one_time": 1, "free": 0}
        if priority.get(plan, 1) > priority.get(existing, 0):
            user_plans[uid] = plan if plan else "paid"

    rows = []
    for u in (users_res.data or []):
        uid = u["id"]
        rows.append({
            "id":           uid,
            "email":        u.get("email", ""),
            "name":         u.get("name", ""),
            "auth_type":    u.get("auth_type", "google"),
            "plan":         user_plans.get(uid, "free"),
            "domain_count": domain_counts.get(uid, 0),
            "paid_domains": paid_counts.get(uid, 0),
            "created_at":   u.get("created_at", ""),
            "last_login":   u.get("last_login", ""),
            "deleted_at":   u.get("deleted_at"),
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
    # Avoid embedded join (select *, users(...)) — PostgREST range header can interact
    # unexpectedly with embedded resources. Batch-fetch users separately instead.
    domains = db.table("domains").select("id,domain,country,user_id,created_at") \
        .order("created_at", desc=True).range(offset, offset + per_page - 1).execute()
    total   = db.table("domains").select("id", count="exact").execute()

    domain_ids = [d["id"] for d in (domains.data or [])]
    user_ids   = list({d["user_id"] for d in (domains.data or []) if d.get("user_id")})

    # Batch-fetch user info
    user_map: dict = {}
    if user_ids:
        users_res = db.table("users").select("id,email,name").in_("id", user_ids).execute()
        for u in (users_res.data or []):
            user_map[u["id"]] = u

    # Batch-fetch latest scan per domain (no N+1)
    scan_map: dict = {}
    if domain_ids:
        scans_res = db.table("scans").select("domain_id,risk_score,scanned_at") \
            .in_("domain_id", domain_ids).order("scanned_at", desc=True).limit(per_page * 5).execute()
        for s in (scans_res.data or []):
            did = s["domain_id"]
            if did not in scan_map:
                scan_map[did] = s

    # Batch-fetch paid domains
    paid_set: set = set()
    if domain_ids:
        paid_res = db.table("purchases").select("domain_id").in_("domain_id", domain_ids).execute()
        paid_set = {p["domain_id"] for p in (paid_res.data or []) if p.get("domain_id")}

    rows = []
    for d in (domains.data or []):
        did  = d["id"]
        scan = scan_map.get(did, {})
        usr  = user_map.get(d.get("user_id", ""), {})
        rows.append({
            "id":          did,
            "domain":      d["domain"],
            "country":     d.get("country", ""),
            "user_email":  usr.get("email", ""),
            "user_name":   usr.get("name", ""),
            "risk_score":  scan.get("risk_score"),
            "scanned_at":  scan.get("scanned_at"),
            "paid":        did in paid_set,
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
    domains   = db.table("domains").select("id,domain,created_at,industry").execute()
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

    # Industry × risk breakdown
    # domain_id → industry (only domains that have an industry tag)
    domain_industry = {d["id"]: d["industry"] for d in domains.data if d.get("industry")}
    industry_stats: dict[str, dict] = {}
    for s in scanned_domains:
        ind = domain_industry.get(s.get("domain_id", ""))
        if not ind:
            continue
        if ind not in industry_stats:
            industry_stats[ind] = {"industry": ind, "domains": 0, "critical": 0, "warning": 0, "clean": 0, "total_score": 0}
        score = s.get("risk_score") or 0
        industry_stats[ind]["domains"]     += 1
        industry_stats[ind]["total_score"] += score
        if score >= 70:
            industry_stats[ind]["critical"] += 1
        elif score >= 30:
            industry_stats[ind]["warning"]  += 1
        else:
            industry_stats[ind]["clean"]    += 1
    # Compute avg and sort by critical desc, then total domains desc
    industry_risk = []
    for ind, s in industry_stats.items():
        n = s["domains"]
        industry_risk.append({
            "industry": ind,
            "domains":  n,
            "critical": s["critical"],
            "warning":  s["warning"],
            "clean":    s["clean"],
            "avg_risk": round(s["total_score"] / n, 1) if n else 0,
        })
    industry_risk.sort(key=lambda x: (x["critical"], x["domains"]), reverse=True)

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
        api_key_rows = db.table("api_keys").select("user_id,calls_this_month,limit_per_month,key_prefix,created_at,revoked_at").execute()
        api_keys_data = api_key_rows.data or []
    except Exception:
        api_keys_data = []
    active_keys    = [k for k in api_keys_data if not k.get("revoked_at")]
    total_api_calls = sum(k.get("calls_this_month") or 0 for k in api_keys_data)
    new_keys_7d    = within_days(api_keys_data, "created_at", 7)
    new_keys_30d   = within_days(api_keys_data, "created_at", 30)
    # Top 5 API users by calls this month
    top_api = sorted(
        [{"user_id": k.get("user_id","?"), "key": (k.get("key_prefix") or "")[:12]+"…",
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
        "industry_risk":   industry_risk,
    }


@app.get("/admin/api-keys")
def admin_list_api_keys(authorization: str = Header(None)):
    """List all API keys with owner info. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    rows = db.table("api_keys").select("id,key_prefix,user_id,calls_this_month,limit_per_month,created_at,revoked_at,last_used_at").execute()
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
        k["active"]     = not bool(k.get("revoked_at"))
        k["key"]        = k.get("key_prefix", "")   # frontend compat alias
    keys.sort(key=lambda k: k.get("calls_this_month") or 0, reverse=True)
    return {"keys": keys}


class AdminKeyLimitBody(BaseModel):
    limit: int

@app.patch("/admin/api-keys/{key_id}/limit")
def admin_set_key_limit(key_id: str, body: AdminKeyLimitBody, authorization: str = Header(None)):
    """Set monthly call limit for any API key. Admin only."""
    require_admin(authorization)
    if body.limit < 1:
        raise HTTPException(400, "Limit must be at least 1")
    db = get_admin_db()
    db.table("api_keys").update({"limit_per_month": body.limit}).eq("id", key_id).execute()
    return {"id": key_id, "limit": body.limit}


@app.post("/admin/api-keys/{key_id}/reset-calls")
def admin_reset_key_calls(key_id: str, authorization: str = Header(None)):
    """Reset monthly call counter to 0. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    db.table("api_keys").update({"calls_this_month": 0}).eq("id", key_id).execute()
    return {"reset": key_id}


@app.patch("/admin/api-keys/{key_id}/toggle")
def admin_toggle_key(key_id: str, authorization: str = Header(None)):
    """Enable or disable an API key via revoked_at. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    existing = db.table("api_keys").select("revoked_at").eq("id", key_id).execute()
    if not existing.data:
        raise HTTPException(404, "Key not found")
    currently_revoked = bool(existing.data[0].get("revoked_at"))
    new_revoked_at = None if currently_revoked else datetime.now(timezone.utc).isoformat()
    db.table("api_keys").update({"revoked_at": new_revoked_at}).eq("id", key_id).execute()
    return {"id": key_id, "active": currently_revoked}  # active = was revoked, now enabled


@app.delete("/admin/api-keys/{key_id}")
def admin_revoke_key(key_id: str, authorization: str = Header(None)):
    """Soft-revoke any API key. Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    db.table("api_keys").update({"revoked_at": datetime.now(timezone.utc).isoformat()}).eq("id", key_id).execute()
    return {"revoked": key_id}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Soft-delete a user (marks deleted_at, wipes sessions). No data is removed. Admin only."""
    require_admin(authorization)
    db = get_admin_db()

    user_row = db.table("users").select("email,name,deleted_at").eq("id", user_id).execute()
    if not user_row.data:
        raise HTTPException(404, "User not found")
    u = user_row.data[0]
    if u.get("deleted_at"):
        raise HTTPException(409, "User is already deleted")

    user_email = u["email"]
    user_name  = u.get("name", "")

    db.table("users").update({
        "deleted_at": datetime.now(timezone.utc).isoformat()
    }).eq("id", user_id).execute()
    db.table("sessions").delete().eq("user_id", user_id).execute()

    background_tasks.add_task(send_account_deletion_email, user_email, user_name)
    return {"deleted": user_id}


@app.post("/admin/users/{user_id}/restore")
def admin_restore_user(user_id: str, authorization: str = Header(None)):
    """Restore a soft-deleted user (clear deleted_at). Admin only."""
    require_admin(authorization)
    db = get_admin_db()
    user_row = db.table("users").select("id,deleted_at").eq("id", user_id).execute()
    if not user_row.data:
        raise HTTPException(404, "User not found")
    if not user_row.data[0].get("deleted_at"):
        raise HTTPException(409, "User is not deleted")
    db.table("users").update({"deleted_at": None}).eq("id", user_id).execute()
    return {"restored": user_id}


class AdminUpdateUserBody(BaseModel):
    email: Optional[str] = None
    name:  Optional[str] = None

@app.patch("/admin/users/{user_id}")
def admin_update_user(user_id: str, body: AdminUpdateUserBody, authorization: str = Header(None)):
    """Update a user's email and/or name. Admin only."""
    import re as _re
    require_admin(authorization)
    db = get_admin_db()

    row = db.table("users").select("id,email").eq("id", user_id).execute()
    if not row.data:
        raise HTTPException(404, "User not found")

    updates: dict = {}
    if body.email is not None:
        email = body.email.strip().lower()
        if not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            raise HTTPException(400, "Invalid email address")
        updates["email"] = email
    if body.name is not None:
        name = body.name.strip()
        if name:
            updates["name"] = name

    if updates:
        db.table("users").update(updates).eq("id", user_id).execute()
    return {"updated": user_id}


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
    """Fetch AI cost/usage summary from Portkey analytics API (last 30 days)."""
    user = get_user_from_header(authorization)
    if not is_admin(user["sub"]):
        raise HTTPException(403, "Admin only")
    if not PORTKEY_API_KEY or not PORTKEY_WORKSPACE:
        msg = "Portkey not configured (set PORTKEY_API_KEY and PORTKEY_WORKSPACE_SLUG in Render)"
        return {"error": msg, "total_requests": 0, "total_cost": 0, "total_tokens": 0, "logs": []}
    try:
        now = datetime.now(timezone.utc)
        period_start = (now.replace(day=1, hour=0, minute=0, second=0, microsecond=0))
        params = {
            "workspace_slug":         PORTKEY_WORKSPACE,
            "time_of_generation_min": period_start.isoformat(),
            "time_of_generation_max": now.isoformat(),
        }
        pk_h = {"x-portkey-api-key": PORTKEY_API_KEY}
        cost_r = httpx.get("https://api.portkey.ai/v1/analytics/graphs/cost",     headers=pk_h, params=params, timeout=10)
        req_r  = httpx.get("https://api.portkey.ai/v1/analytics/graphs/requests", headers=pk_h, params=params, timeout=10)
        tok_r  = httpx.get("https://api.portkey.ai/v1/analytics/graphs/tokens",   headers=pk_h, params=params, timeout=10)
        cost_data = cost_r.json() if cost_r.status_code == 200 else {}
        req_data  = req_r.json()  if req_r.status_code == 200 else {}
        tok_data  = tok_r.json()  if tok_r.status_code == 200 else {}
        total_cost    = float((cost_data.get("summary") or {}).get("total", 0) or 0) / 100.0
        total_requests = int((req_data.get("summary") or {}).get("total", 0) or 0)
        total_tokens   = int((tok_data.get("summary") or {}).get("total", 0) or 0)
        return {
            "total_requests": total_requests,
            "total_tokens":   total_tokens,
            "total_cost":     round(total_cost, 4),
            "logs":           [],  # use /admin/llm-stats for detailed breakdown
        }
    except Exception as e:
        return {"error": str(e), "total_requests": 0, "total_cost": 0, "total_tokens": 0, "logs": []}


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
    if not PORTKEY_WORKSPACE:
        return {
            "configured": False,
            "message": "PORTKEY_WORKSPACE_SLUG not set — add your Portkey workspace slug to Render env vars (find it in Portkey dashboard → Settings → Workspace)",
        }

    pk_headers = {"x-portkey-api-key": PORTKEY_API_KEY}
    now = datetime.now(timezone.utc)

    if period == "day":
        period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        period_label = "today"
        ts_slice = 13   # group by hour "YYYY-MM-DDTHH"
    elif period == "year":
        period_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        period_label = "this year"
        ts_slice = 7    # group by month "YYYY-MM"
    else:
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        period_label = "this month"
        ts_slice = 10   # group by day "YYYY-MM-DD"

    base_params = {
        "workspace_slug":          PORTKEY_WORKSPACE,
        "time_of_generation_min":  period_start.isoformat(),
        "time_of_generation_max":  now.isoformat(),
    }
    group_params = {**base_params, "page_size": 100, "current_page": 0}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            (cost_r, req_r, tok_r,
             domain_r, user_r, type_r) = await asyncio.gather(
                client.get("https://api.portkey.ai/v1/analytics/graphs/cost",              headers=pk_headers, params=base_params),
                client.get("https://api.portkey.ai/v1/analytics/graphs/requests",          headers=pk_headers, params=base_params),
                client.get("https://api.portkey.ai/v1/analytics/graphs/tokens",            headers=pk_headers, params=base_params),
                client.get("https://api.portkey.ai/v1/analytics/groups/metadata/domain",   headers=pk_headers, params=group_params),
                client.get("https://api.portkey.ai/v1/analytics/groups/metadata/_user",    headers=pk_headers, params=group_params),
                client.get("https://api.portkey.ai/v1/analytics/groups/metadata/report_type", headers=pk_headers, params=group_params),
            )
    except Exception as e:
        raise HTTPException(502, f"Portkey API error: {e}")

    def _j(r): return r.json() if r.status_code == 200 else {}
    cost_data   = _j(cost_r)
    req_data    = _j(req_r)
    tok_data    = _j(tok_r)
    domain_data = _j(domain_r)
    user_data   = _j(user_r)
    type_data   = _j(type_r)

    # Totals — Portkey cost values are in USD cents, divide by 100
    total_cost_cents = float((cost_data.get("summary") or {}).get("total", 0) or 0)
    total_cost       = total_cost_cents / 100.0
    total_requests   = int((req_data.get("summary") or {}).get("total", 0) or 0)
    total_tokens     = int((tok_data.get("summary") or {}).get("total", 0) or 0)

    # Time series from cost + requests graph data_points
    cost_pts = {}
    for p in (cost_data.get("data_points") or []):
        dk = (p.get("timestamp") or "")[:ts_slice]
        if dk:
            cost_pts[dk] = cost_pts.get(dk, 0.0) + float(p.get("total", 0) or 0) / 100.0
    req_pts = {}
    for p in (req_data.get("data_points") or []):
        dk = (p.get("timestamp") or "")[:ts_slice]
        if dk:
            req_pts[dk] = req_pts.get(dk, 0) + int(p.get("total", 0) or 0)
    all_dates  = sorted(set(cost_pts) | set(req_pts))
    time_series = [
        {"date": d, "cost": round(cost_pts.get(d, 0.0), 6), "requests": req_pts.get(d, 0)}
        for d in all_dates
    ]

    # Group breakdown helper — cost in groups is also in cents
    def _parse_groups(gdata, name_field):
        rows = []
        for item in (gdata.get("data") or []):
            c    = float(item.get("cost", 0) or 0) / 100.0
            reqs = int(item.get("requests", 0) or 0)
            avg_tok = float(item.get("avg_tokens", 0) or 0)
            rows.append({
                name_field:  item.get("metadata_value", ""),
                "requests":  reqs,
                "tokens":    int(avg_tok * reqs),
                "cost":      round(c, 6),
            })
        rows.sort(key=lambda x: x["cost"], reverse=True)
        return rows

    domain_breakdown = _parse_groups(domain_data, "domain")
    type_breakdown   = _parse_groups(type_data,   "report_type")
    type_breakdown.sort(key=lambda x: x["requests"], reverse=True)
    user_rows        = _parse_groups(user_data,   "user_id")

    # Enrich user breakdown with emails
    db = get_admin_db()
    user_ids  = [u["user_id"] for u in user_rows if u["user_id"] and u["user_id"] != "anonymous"]
    email_map = {}
    if user_ids:
        try:
            rows = db.table("users").select("id,email").in_("id", user_ids).execute()
            for row in (rows.data or []):
                email_map[row["id"]] = row.get("email", "")
        except Exception:
            pass
    user_breakdown = []
    for u in user_rows:
        uid = u["user_id"]
        user_breakdown.append({
            "user_id":  uid,
            "email":    email_map.get(uid, (uid[:8] + "…") if len(uid) > 8 else uid),
            "requests": u["requests"],
            "tokens":   u["tokens"],
            "cost":     u["cost"],
        })

    return {
        "configured":    True,
        "period":        period_label,
        "period_key":    period,
        "totals": {
            "cost":              round(total_cost, 6),
            "tokens":            total_tokens,
            "prompt_tokens":     0,   # not split in graph endpoints
            "completion_tokens": 0,
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
        db = get_admin_db()
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
    db = get_admin_db()
    for key, val in [("report_subject", body.subject), ("report_body", body.body), ("report_footer", body.footer)]:
        # Try update first; insert if no row exists yet
        res = db.table("admin_settings").update({"value": val, "updated_at": datetime.now(timezone.utc).isoformat()}).eq("key", key).execute()
        if not res.data:
            db.table("admin_settings").insert({"key": key, "value": val, "updated_at": datetime.now(timezone.utc).isoformat()}).execute()
    _report_email_cache = {"subject": body.subject, "body": body.body, "footer": body.footer}
    return {"saved": True}


@app.delete("/admin/report-email-template")
def reset_report_email_template(authorization: str = Header(None)):
    global _report_email_cache
    require_admin(authorization)
    db = get_admin_db()
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
    admin = is_admin(u["id"])
    from pipeline import _get_scanner_ip
    return {
        "id":            u["id"],
        "email":         u["email"],
        "name":          u.get("name", ""),
        "avatar":        u.get("avatar", ""),
        "is_admin":      admin,
        "is_super_admin": admin,   # currently same as is_admin (owner only); extend later for multi-admin tiers
        "auth_type":     u.get("auth_type", "google"),
        "scanner_ip":    _get_scanner_ip(),
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
def delete_account(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Soft-delete the current user's account. Marks deleted_at, wipes sessions; all data is retained."""
    user = get_user_from_header(authorization)
    db   = get_db()
    uid  = user["sub"]

    user_row = db.table("users").select("email,name,deleted_at").eq("id", uid).execute()
    if not user_row.data:
        raise HTTPException(404, "User not found")
    u = user_row.data[0]
    if u.get("deleted_at"):
        raise HTTPException(409, "Account is already deleted")

    user_email = u["email"]
    user_name  = u.get("name", "")

    # Soft-delete: stamp deleted_at and invalidate all sessions
    db.table("users").update({
        "deleted_at": datetime.now(timezone.utc).isoformat()
    }).eq("id", uid).execute()
    db.table("sessions").delete().eq("user_id", uid).execute()

    background_tasks.add_task(send_account_deletion_email, user_email, user_name)
    return {"deleted": True}


@app.get("/domains")
def list_domains(authorization: str = Header(None)):
    """List all domains for the logged-in user."""
    user = get_user_from_header(authorization)
    # Use service-role DB so the query works regardless of Supabase RLS config.
    # Security is enforced via the application-level user_id filter below.
    db = get_admin_db()

    # Fetch domains with lightweight scan metadata (no checks blob) and purchase flags.
    # Omitting checks(*) here is the key optimisation — checks are large JSON and we
    # only need them for the single latest scan per domain, fetched separately below.
    domains_res = db.table("domains")\
        .select("id,domain,country,industry,created_at,primary_contact,contact_emails,scans(id,scanned_at,risk_score),purchases(paid_at)")\
        .eq("user_id", user["sub"])\
        .order("created_at", desc=True)\
        .execute()

    if not domains_res.data:
        return {"domains": []}

    # Build a map of domain_id → latest scan row (no checks yet)
    latest_scan_by_domain: dict = {}
    for d in domains_res.data:
        scans = d.get("scans") or []
        if scans:
            # Guard against scans with null scanned_at
            latest_scan_by_domain[d["id"]] = max(
                scans, key=lambda s: s.get("scanned_at") or ""
            )

    # Single targeted query: fetch checks only for the latest scan of each domain
    latest_checks_map: dict = {}
    if latest_scan_by_domain:
        scan_ids = [s["id"] for s in latest_scan_by_domain.values()]
        checks_res = db.table("scans").select("id,checks").in_("id", scan_ids).execute()
        for row in (checks_res.data or []):
            raw = row.get("checks", [])
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    raw = []
            latest_checks_map[row["id"]] = raw if isinstance(raw, list) else []

    result = []
    for d in domains_res.data:
        scans      = d.get("scans") or []
        latest_scan = latest_scan_by_domain.get(d["id"])
        is_paid    = any(p.get("paid_at") for p in (d.get("purchases") or []))

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

        latest_checks = latest_checks_map.get(latest_scan["id"], []) if latest_scan else []

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
            "industry":        d.get("industry"),
            "primary_contact": d.get("primary_contact"),
            "contact_emails":  cached_contact_emails or [],
            "scan_history": [
                {"date": s["scanned_at"], "risk": s["risk_score"]}
                for s in sorted(scans, key=lambda s: s.get("scanned_at") or "")
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

    # Free tier: 1 domain max unless user has an active paid plan or is admin
    FREE_DOMAIN_LIMIT = 1
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
                    detail="Free accounts include 1 domain with 1 free scan. Upgrade to Professional ($49/mo, billed yearly) to monitor up to 10 domains."
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


class IndustryBody(BaseModel):
    industry: str | None = None

@app.patch("/domains/{domain_id}/industry")
def update_domain_industry(domain_id: str, body: IndustryBody, authorization: str = Header(None)):
    """Set the industry tag for a domain."""
    user = get_user_from_header(authorization)
    db = get_admin_db()
    domain = db.table("domains").select("id").eq("id", domain_id).eq("user_id", user["sub"]).execute()
    if not domain.data:
        raise HTTPException(404, "Domain not found")
    industry = body.industry or None  # allow clearing with null/empty
    try:
        db.table("domains").update({"industry": industry}).eq("id", domain_id).execute()
    except Exception as e:
        _reset_db_on_ssl_error(e)
        raise HTTPException(500, f"Could not save industry: {str(e)[:200]}")
    return {"industry": industry}


@app.get("/domains/{domain_id}/scan-status")
def get_scan_status(domain_id: str, authorization: str = Header(None)):
    """Return live scan progress for a domain.

    While scanning: estimated percentage, current check index (0-21), elapsed seconds.
    When idle:      scanning=false, pct=100.
    """
    user = get_user_from_header(authorization)
    db   = get_db()
    row  = db.table("domains").select("user_id,domain").eq("id", domain_id).execute()
    if not row.data or row.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found or not your domain")

    TOTAL_CHECKS     = 22
    ESTIMATED_SECS   = 90.0   # typical full scan duration

    if domain_id in _active_scans:
        info    = _active_scans[domain_id]
        started = info.get("started_at", "")
        elapsed = 0
        if started:
            try:
                from dateutil import parser as dtparse
                elapsed = (datetime.now(timezone.utc) - dtparse.parse(started)).total_seconds()
            except Exception:
                pass
        pct       = min(95, int((elapsed / ESTIMATED_SECS) * 100))
        check_idx = min(TOTAL_CHECKS - 1, int((elapsed / ESTIMATED_SECS) * TOTAL_CHECKS))
        remaining = max(0, int(ESTIMATED_SECS - elapsed))
        return {
            "scanning":       True,
            "pct":            pct,
            "check_idx":      check_idx,       # 0-indexed current check (0–21)
            "total_checks":   TOTAL_CHECKS,
            "elapsed_seconds": int(elapsed),
            "remaining_seconds": remaining,
        }

    return {
        "scanning":       False,
        "pct":            100,
        "check_idx":      TOTAL_CHECKS,
        "total_checks":   TOTAL_CHECKS,
        "elapsed_seconds": 0,
        "remaining_seconds": 0,
    }


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

    # Also enrich scan_results with the discovered contacts
    if contacts:
        sr_update = {"contact_emails": json.dumps(contacts)}
        if contacts[0]:
            sr_update["contact_email"] = contacts[0]
        db.table("scan_results").update(sr_update).eq("domain", d["domain"]).execute()

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
        "ports", "subdomains", "cms",
        # paid: ip_intel
    }

    if is_paid:
        visible_checks = checks
    else:
        visible_checks = [c for c in checks if c.get("check") in FREE_CHECKS]

    non_ai = [c for c in visible_checks if c.get("check") != "ai_summary"]

    # ── IP / datacenter geo (best-effort, non-blocking) ──────────────────────
    import re as _re
    ip_address = None; ip_city = None; ip_org = None
    domain_name = d["domain"]

    # 1. Try pipeline scan_results cache (fast, no external call)
    try:
        from outreach import get_db as _odb
        _sr = _odb().table("scan_results")\
            .select("ip_address,ip_city,ip_org")\
            .eq("domain", domain_name)\
            .limit(1).execute()
        if _sr.data and _sr.data[0].get("ip_address"):
            r0 = _sr.data[0]
            ip_address = r0.get("ip_address") or None
            ip_city    = r0.get("ip_city") or ""
            ip_org     = r0.get("ip_org") or ""
    except Exception:
        pass  # migration not run or domain not in pipeline — fall through to live lookup

    # 2. Live fallback: resolve IP and call ip-api.com
    if not ip_address:
        try:
            import socket as _sock, requests as _req
            _ip = _sock.gethostbyname(domain_name)
            _geo = _req.get(
                f"http://ip-api.com/json/{_ip}?fields=status,lat,lon,city,as,org",
                timeout=5
            ).json()
            if _geo.get("status") == "success":
                ip_address = _ip
                ip_city    = _geo.get("city") or ""
                _raw_org   = _geo.get("org") or _geo.get("as") or ""
                ip_org     = _re.sub(r"^AS\d+\s+", "", _raw_org)
        except Exception:
            pass

    return {
        "domain":      d["domain"],
        "risk_score":  latest["risk_score"],
        "scanned_at":  latest["scanned_at"],
        "paid":        is_paid,
        "checks":      visible_checks,
        "critical":    sum(1 for c in non_ai if c.get("status") == "critical"),
        "warnings":    sum(1 for c in non_ai if c.get("status") == "warning"),
        "locked_count": len(checks) - len(visible_checks) if not is_paid else 0,
        "ip_address":  ip_address,
        "ip_city":     ip_city,
        "ip_org":      ip_org,
    }


@app.get("/domains/{domain_id}/typosquat")
def get_domain_typosquat(domain_id: str, authorization: str = Header(None)):
    """
    Return full typosquat analysis for a domain:
    - registered: candidates that resolve via DNS (threats)
    - available:  candidates not registered (buy suggestions)
    """
    import socket as _socket
    import concurrent.futures as _cf
    import urllib.parse as _up

    user = get_user_from_header(authorization)
    db   = get_db()

    domain_row = db.table("domains").select("domain").eq("id", domain_id).eq("user_id", user["sub"]).single().execute()
    if not domain_row.data:
        raise HTTPException(404, "Domain not found")

    domain = domain_row.data["domain"].lower().strip()
    parts  = domain.split(".")
    if len(parts) < 2:
        return {"domain": domain, "registered": [], "available": []}

    name = parts[0]
    tld  = ".".join(parts[1:])

    candidates: set = set()

    # 1. Character substitutions (leet + homoglyphs)
    subs = {"a": ["4", "@"], "e": ["3"], "i": ["1", "l"], "o": ["0"], "s": ["5", "$"], "l": ["1"]}
    for i, c in enumerate(name):
        for alt in subs.get(c, []):
            candidates.add(f"{name[:i]}{alt}{name[i+1:]}.{tld}")

    # 2. Missing / doubled characters
    for i in range(len(name)):
        candidates.add(f"{name[:i]+name[i+1:]}.{tld}")
        candidates.add(f"{name[:i]+name[i]+name[i]+name[i+1:]}.{tld}")

    # 3. Adjacent keyboard transpositions
    for i in range(len(name) - 1):
        t = list(name); t[i], t[i+1] = t[i+1], t[i]
        candidates.add("".join(t) + "." + tld)

    # 4. TLD variations
    for alt_tld in ["com", "net", "org", "io", "eu", "co", "app", "dev", "security"]:
        if alt_tld != tld:
            candidates.add(f"{name}.{alt_tld}")

    # 5. Hyphen insertion
    for i in range(1, len(name)):
        candidates.add(f"{name[:i]}-{name[i:]}.{tld}")

    # 6. Common prefix/suffix squats
    tld_base = tld.split(".")[0]
    for affix in [f"{name}-{tld_base}", f"{tld_base}-{name}", f"{name}online",
                  f"{name}secure", f"my{name}", f"{name}app", f"get{name}", f"{name}help"]:
        candidates.add(f"{affix}.com")

    # Remove the original domain itself
    candidates.discard(domain)
    # Keep max 60 unique candidates
    candidates = list(candidates)[:60]

    # Check DNS (registered) + RDAP (available) in parallel
    def _check(candidate):
        registered = False
        available  = False
        try:
            _socket.getaddrinfo(candidate, None, _socket.AF_INET, _socket.SOCK_STREAM)
            registered = True
        except _socket.gaierror:
            # Not in DNS — check RDAP for availability
            try:
                r = requests.get(
                    f"https://rdap.org/domain/{candidate}",
                    timeout=5, allow_redirects=True,
                    headers={"Accept": "application/json", "User-Agent": "SwarmHawk/1.0"},
                )
                if r.status_code in (404, 400):
                    available = True
            except Exception:
                pass
        return candidate, registered, available

    registered_list = []
    available_list  = []

    with _cf.ThreadPoolExecutor(max_workers=20) as ex:
        for cand, is_registered, is_available in ex.map(_check, candidates):
            if is_registered:
                registered_list.append(cand)
            elif is_available:
                available_list.append(cand)

    # Sort — shorter / most similar first
    registered_list.sort(key=len)
    available_list.sort(key=len)

    def _buy_url(d):
        return "https://www.namecheap.com/domains/registration/results/?domain=" + _up.quote(d)

    return {
        "domain":     domain,
        "registered": registered_list,
        "available":  [{"domain": d, "buy_url": _buy_url(d)} for d in available_list[:20]],
        "total_checked": len(candidates),
    }


@app.get("/domains/{domain_id}/report/pdf")
def download_report_pdf(domain_id: str, authorization: str = Header(None)):
    """Download the latest scan report as a PDF attachment."""
    from fastapi.responses import Response as _Resp
    user = get_user_from_header(authorization)
    db   = get_db()

    domain_row = db.table("domains")\
        .select("*, scans(*)")\
        .eq("id", domain_id)\
        .eq("user_id", user["sub"])\
        .single()\
        .execute()

    if not domain_row.data:
        raise HTTPException(404, "Domain not found")

    d = domain_row.data
    scans = sorted(d.get("scans", []), key=lambda s: s.get("scanned_at") or "", reverse=True)
    if not scans:
        raise HTTPException(400, "No scan data yet — run a scan first")

    latest = scans[0]
    raw = latest.get("checks", [])
    if isinstance(raw, str):
        try: raw = json.loads(raw)
        except Exception: raw = []
    checks = raw if isinstance(raw, list) else []

    try:
        pdf_bytes = _generate_pdf(
            d["domain"],
            latest.get("risk_score") or 0,
            latest.get("scanned_at", ""),
            checks,
        )
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {e}")

    date_str   = (latest.get("scanned_at") or "")[:10] or "report"
    user_slug  = _user_slug(user["sub"], db)
    filename   = f"swarmhawk-{d['domain']}-{date_str}-{user_slug}.pdf"
    return _Resp(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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


def _user_slug(uid: str, db) -> str:
    """Derive a short safe filename slug from the user's name or email."""
    import re as _re
    try:
        row = db.table("users").select("name,email").eq("id", uid).single().execute()
        if row.data:
            raw = (row.data.get("name") or row.data.get("email") or "user").split()[0]
            raw = raw.split("@")[0]
            slug = _re.sub(r'[^a-zA-Z0-9_\-]', '', raw).lower()[:20]
            return slug or "user"
    except Exception:
        pass
    return "user"


def _generate_pdf(domain: str, risk_score: int, scanned_at: str, checks: list) -> bytes:
    """Build a dark-themed PDF security report matching SwarmHawk's design system."""
    import os as _os
    from fpdf import FPDF

    # ── Design system constants (from DESIGN.md) ────────────────────────────
    C_DARK    = (8,   8,  16)    # --dark    page background
    C_SURFACE = (15,  15, 26)    # --surface header / footer band
    C_CARD    = (19,  19, 31)    # --card    check card background
    C_CARD2   = (24,  24, 40)    # raised within card
    C_BORDER  = (38,  38, 55)    # --border approximated (rgba 255,255,255,.07 on --dark)
    C_TEXT    = (232, 232, 240)  # --text    primary text
    C_MUTED   = (136, 136, 160)  # --muted   secondary text
    C_LIME    = (163, 230, 53)   # --lime    accent
    C_RED     = (248, 113, 113)  # --red     critical
    C_AMBER   = (251, 191, 36)   # --amber   warning
    C_ORANGE  = (251, 146, 60)   # high
    C_GREEN   = (163, 230, 53)   # clean / ok  (same lime)
    C_GREY    = (100, 100, 120)  # error / unknown

    STATUS_COLOR = {
        "critical": C_RED,
        "warning":  C_AMBER,
        "ok":       C_GREEN,
        "error":    C_GREY,
    }
    STATUS_LABEL = {
        "critical": "CRITICAL",
        "warning":  "WARNING",
        "ok":       "OK",
        "error":    "ERROR",
    }
    CHECK_LABELS = {
        "ssl": "SSL/TLS", "ssl_grade": "SSL Grade", "tls_version": "TLS Version",
        "headers": "Security Headers", "csp": "Content-Security-Policy",
        "x_frame_options": "X-Frame-Options", "x_content_type": "X-Content-Type",
        "referrer_policy": "Referrer-Policy", "permissions_policy": "Permissions-Policy",
        "hsts": "HSTS", "cors": "CORS", "http_security": "HTTP Security",
        "https_redirect": "HTTPS Redirect", "www_redirect": "WWW Redirect",
        "dns": "DNS", "dnssec": "DNSSEC", "spf": "SPF", "dmarc": "DMARC",
        "dkim": "DKIM", "mx": "MX Records", "caa": "CAA Records", "bimi": "BIMI",
        "email_security": "Email Security", "cert_valid": "Certificate Validity",
        "cert_expiry": "Certificate Expiry", "cert_chain": "Certificate Chain",
        "breach": "Breach Exposure", "typosquat": "Typosquatting",
        "performance": "Response Time", "whois": "WHOIS / RDAP",
        "urlhaus": "URLhaus Malware", "spamhaus": "Spamhaus DBL",
        "safebrowsing": "Google Safe Browsing", "virustotal": "VirusTotal",
        "paranoidlab": "Dark Web Intel", "ip_intel": "IP Intelligence",
        "cve": "CVE Scan", "cve_exposure": "CVE Exposure",
        "cms": "CMS Detection", "cms_version": "CMS Version",
        "server_header": "Server Header", "software_disclosure": "Software Disclosure",
        "waf": "WAF Detection", "open_ports": "Open Ports",
        "ports": "Critical Ports", "admin_panel": "Admin Panel",
        "directory_listing": "Directory Listing", "subdomains": "Subdomains",
        "nuclei": "Active CVE Scan (Nuclei)",
        "sast": "SAST — Source Exposure", "sca": "SCA — Dependency CVEs",
        "dast": "DAST — App Testing", "iac": "IaC — Config Exposure",
        "injection": "A03/A05: Injection", "auth_security": "A07: Auth Failures",
        "integrity": "A08: Data Integrity", "ssrf": "A10/A01: SSRF",
        "jwt_security": "A08/A04: JWT Security", "deserialization": "A08: Deserialization",
        "default_creds": "A02/A07: Default Creds", "rate_limiting": "A06: Rate Limiting",
        "llm_security": "LLM01-10: AI Security",
    }

    # ── Date formatting ──────────────────────────────────────────────────────
    try:
        from dateutil import parser as _dtp
        scan_date = _dtp.parse(scanned_at).strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        scan_date = scanned_at[:10] if scanned_at else "—"

    non_ai   = [c for c in checks if c.get("check") != "ai_summary"]
    criticals = sum(1 for c in non_ai if c.get("status") == "critical")
    warnings  = sum(1 for c in non_ai if c.get("status") == "warning")
    cleans    = sum(1 for c in non_ai if c.get("status") == "ok")

    # Score color
    if   risk_score >= 60: score_col = C_RED
    elif risk_score >= 30: score_col = C_AMBER
    elif risk_score >= 10: score_col = C_ORANGE
    else:                  score_col = C_GREEN

    # ── Font helpers ─────────────────────────────────────────────────────────
    _FONTS_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "fonts")

    class DarkPDF(FPDF):
        def header(self):
            pass   # custom header drawn manually on first page only
        def footer(self):
            # ── Per-page footer bar ─────────────────────────────────────────
            self.set_y(-14)
            self.set_fill_color(*C_SURFACE)
            self.rect(0, self.get_y() - 1, 210, 16, style="F")
            self.set_font("Inter", "", 7)
            self.set_text_color(*C_MUTED)
            self.cell(0, 6, "SwarmHawk - European Cybersecurity Intelligence - www.swarmhawk.com", align="C", new_x="LMARGIN", new_y="NEXT")
            self.cell(0, 5, f"Page {self.page_no()} - Confidential - Scan date: {scan_date}", align="C")

    pdf = DarkPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(18, 18, 18)

    _fonts_ok = False
    try:
        pdf.add_font("Inter",         "",  _os.path.join(_FONTS_DIR, "Inter-Regular.ttf"))
        pdf.add_font("Inter",         "B", _os.path.join(_FONTS_DIR, "Inter-Bold.ttf"))
        pdf.add_font("InterEB",       "",  _os.path.join(_FONTS_DIR, "Inter-ExtraBold.ttf"))
        pdf.add_font("JetBrainsMono", "",  _os.path.join(_FONTS_DIR, "JetBrainsMono-Regular.ttf"))
        pdf.add_font("JetBrainsMono", "B", _os.path.join(_FONTS_DIR, "JetBrainsMono-Bold.ttf"))
        FONT_BODY  = "Inter"
        FONT_MONO  = "JetBrainsMono"
        FONT_XBOLD = "InterEB"
        _fonts_ok  = True
    except Exception:
        # Fallback if fonts dir not found
        FONT_BODY  = "Helvetica"
        FONT_MONO  = "Courier"
        FONT_XBOLD = "Helvetica"

    pdf.add_page()

    # ── Fill entire first page background ───────────────────────────────────
    pdf.set_fill_color(*C_DARK)
    pdf.rect(0, 0, 210, 297, style="F")

    # ── Header band ─────────────────────────────────────────────────────────
    pdf.set_fill_color(*C_SURFACE)
    pdf.rect(0, 0, 210, 42, style="F")

    # Lime left accent strip
    pdf.set_fill_color(*C_LIME)
    pdf.rect(0, 0, 3, 42, style="F")

    # Wordmark
    pdf.set_xy(10, 10)
    pdf.set_font(FONT_MONO, "B", 13)
    pdf.set_text_color(*C_LIME)
    bullet = "\u25cf" if _fonts_ok else "*"
    pdf.cell(6, 6, bullet)   # ● or * dot
    pdf.set_x(pdf.get_x() + 1)
    pdf.cell(0, 6, "SWARMHAWK", new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(10)
    pdf.set_font(FONT_BODY, "", 8)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 5, _pdf_safe("Security Intelligence Report  -  European Cybersecurity"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(10)
    pdf.set_font(FONT_MONO, "", 7)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 5, _pdf_safe(f"Generated: {scan_date}"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(50)

    # ── Hero: domain + score ─────────────────────────────────────────────────
    pdf.set_x(18)
    pdf.set_font(FONT_BODY, "B", 11)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 6, "DOMAIN", new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(18)
    pdf.set_font(FONT_MONO, "B", 20)
    pdf.set_text_color(*C_TEXT)
    pdf.cell(0, 10, _pdf_safe(domain), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(2)

    # Score + summary row
    pdf.set_x(18)
    # Score box
    pdf.set_fill_color(*C_CARD)
    pdf.set_draw_color(*C_BORDER)
    pdf.set_font(FONT_MONO, "B", 9)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(28, 5, "RISK SCORE", border=0, new_x="RIGHT", new_y="TOP")

    pdf.set_x(18)
    pdf.ln(5)
    pdf.set_font(FONT_MONO, "B", 36)
    pdf.set_text_color(*score_col)
    pdf.cell(35, 14, str(risk_score), new_x="RIGHT", new_y="TOP")

    pdf.set_font(FONT_MONO, "", 13)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(12, 14, "/100", new_x="RIGHT", new_y="TOP")

    # Summary stats inline
    pdf.set_x(pdf.get_x() + 10)
    y_stats = pdf.get_y() + 4
    for label, count, col in [
        ("CRITICAL", criticals, C_RED),
        ("WARNING",  warnings,  C_AMBER),
        ("PASSED",   cleans,    C_LIME),
        ("TOTAL",    len(non_ai), C_MUTED),
    ]:
        pdf.set_xy(pdf.get_x(), y_stats)
        pdf.set_fill_color(*C_CARD)
        bx = pdf.get_x()
        pdf.set_font(FONT_MONO, "B", 18)
        pdf.set_text_color(*col)
        pdf.cell(18, 8, str(count), new_x="RIGHT", new_y="TOP")
        pdf.set_xy(bx, y_stats + 8)
        pdf.set_font(FONT_BODY, "", 7)
        pdf.set_text_color(*C_MUTED)
        pdf.cell(18, 4, label, align="L", new_x="RIGHT", new_y="TOP")
        pdf.set_x(pdf.get_x() + 5)

    pdf.ln(20)

    # Thin lime rule under hero
    pdf.set_draw_color(*C_LIME)
    pdf.set_line_width(0.3)
    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(6)

    # ── Section title: Security Checks ──────────────────────────────────────
    pdf.set_x(18)
    pdf.set_font(FONT_BODY, "", 8)
    pdf.set_text_color(*C_LIME)
    pdf.cell(0, 5, "SECURITY CHECKS", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # ── Checks ──────────────────────────────────────────────────────────────
    for c in non_ai:
        status  = c.get("status", "ok")
        chk_key = c.get("check", "")
        label   = _pdf_safe(CHECK_LABELS.get(chk_key, chk_key.replace("_", " ").upper()))
        title   = _pdf_safe(c.get("title", ""))
        detail  = _pdf_safe(c.get("detail", ""))
        s_color = STATUS_COLOR.get(status, C_GREY)
        s_label = STATUS_LABEL.get(status, status.upper())

        card_x = 18
        card_w = 174
        row_h  = 8

        # Estimate card height
        needs_detail = detail and status in ("critical", "warning")
        card_h = row_h + (10 if needs_detail else 0)

        # Page break guard — add new page and fill background
        if pdf.get_y() + card_h + 4 > 275:
            pdf.add_page()
            pdf.set_fill_color(*C_DARK)
            pdf.rect(0, 0, 210, 297, style="F")
            pdf.ln(4)

        card_y = pdf.get_y()

        # Card background
        pdf.set_fill_color(*C_CARD)
        pdf.set_draw_color(*C_BORDER)
        pdf.rect(card_x, card_y, card_w, card_h + 4, style="F")

        # Severity left strip (3px)
        pdf.set_fill_color(*s_color)
        pdf.rect(card_x, card_y, 3, card_h + 4, style="F")

        # Status badge
        pdf.set_xy(card_x + 5, card_y + 1.5)
        pdf.set_fill_color(*s_color)
        bw = 18
        pdf.set_font(FONT_MONO, "B", 6)
        pdf.set_text_color(*C_DARK)
        pdf.cell(bw, 5, s_label, fill=True, align="C", new_x="RIGHT", new_y="TOP")

        # Check name (monospace, muted)
        pdf.set_x(pdf.get_x() + 2)
        pdf.set_font(FONT_MONO, "", 7)
        pdf.set_text_color(*C_MUTED)
        pdf.cell(38, 5, _pdf_safe(chk_key[:20]), new_x="RIGHT", new_y="TOP")

        # Title (inter, white)
        pdf.set_x(pdf.get_x() + 2)
        remaining = card_w - bw - 38 - 9
        pdf.set_font(FONT_BODY, "B", 8)
        pdf.set_text_color(*C_TEXT)
        pdf.cell(remaining, 5, title[:80], new_x="LMARGIN", new_y="NEXT")

        # Check label (full name, small muted)
        pdf.set_x(card_x + 5 + bw + 2)
        pdf.set_font(FONT_BODY, "", 7)
        pdf.set_text_color(*C_MUTED)
        pdf.cell(80, 4, label[:50], new_x="LMARGIN", new_y="NEXT")

        # Detail (critical/warning only)
        if needs_detail:
            pdf.set_x(card_x + 5)
            pdf.set_font(FONT_BODY, "", 7)
            pdf.set_text_color(*C_MUTED)
            short = detail.replace("\n", "  ").replace("•", "-")[:280]
            pdf.multi_cell(card_w - 8, 4, short)

        pdf.set_y(card_y + card_h + 6)

    # ── AI summary (if present) ──────────────────────────────────────────────
    ai = next((c for c in checks if c.get("check") == "ai_summary"), None)
    if ai and ai.get("detail"):
        if pdf.get_y() > 240:
            pdf.add_page()
            pdf.set_fill_color(*C_DARK)
            pdf.rect(0, 0, 210, 297, style="F")
            pdf.ln(4)

        pdf.ln(4)
        pdf.set_draw_color(*C_LIME)
        pdf.line(18, pdf.get_y(), 192, pdf.get_y())
        pdf.ln(4)
        pdf.set_x(18)
        pdf.set_font(FONT_BODY, "", 8)
        pdf.set_text_color(*C_LIME)
        pdf.cell(0, 5, "AI THREAT ASSESSMENT", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        card_x, card_y = 18, pdf.get_y()
        pdf.set_fill_color(*C_CARD)
        pdf.rect(card_x, card_y, 174, 5, style="F")   # placeholder; multi_cell expands it

        pdf.set_x(card_x + 4)
        pdf.set_y(card_y + 3)
        pdf.set_font(FONT_BODY, "", 8)
        pdf.set_text_color(*C_TEXT)
        ai_text = _pdf_safe(ai.get("detail", ""))[:1200]
        pdf.multi_cell(166, 5, ai_text)

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

    pdf_b64   = base64.b64encode(pdf_bytes).decode()
    user_slug = _user_slug(user["sub"], db)
    filename  = f"swarmhawk-report-{d['domain']}-{scanned_at[:10]}-{user_slug}.pdf"

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
                session = _get_stripe().checkout.Session.retrieve(p["stripe_session_id"])
                if session.customer:
                    return session.customer
            except Exception:
                continue
    # Fallback: look up by email
    u_row = db.table("users").select("email").eq("id", user_id).execute()
    email = u_row.data[0]["email"] if u_row.data else None
    if email:
        customers = _get_stripe().Customer.list(email=email, limit=1)
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
        portal = _get_stripe().billing_portal.Session.create(
            customer=customer, return_url=FRONTEND_URL
        )
        return {"url": portal.url}
    except _get_stripe().error.StripeError as e:
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
        portal = _get_stripe().billing_portal.Session.create(
            customer=customer,
            return_url=f"{FRONTEND_URL}?tab=account",
        )
        return {"url": portal.url}
    except _get_stripe().error.StripeError as e:
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
    plan=scan           → $5/scan one-time payment per domain.
    plan=professional   → $588/year subscription (= $49/mo billed annually), up to 10 domains.
    plan=one_time       → legacy $10 one-time (kept for backward compat).
    plan=annual         → legacy $50/year (kept for backward compat).
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe not configured — set STRIPE_SECRET_KEY in environment")

    user = get_user_from_header(authorization)
    db   = get_db()

    # Fetch email from users table (get_user_from_header only returns sub/id)
    u_row = db.table("users").select("email").eq("id", user["sub"]).execute()
    user_email = u_row.data[0]["email"] if u_row.data else ""

    if body.plan not in ("scan", "professional", "one_time", "annual"):
        raise HTTPException(400, "plan must be 'scan' or 'professional'")

    # For scan/one_time plans, domain_id is required
    if body.plan in ("scan", "one_time"):
        domain_row = db.table("domains")\
            .select("id, domain")\
            .eq("id", body.domain_id)\
            .eq("user_id", user["sub"])\
            .limit(1)\
            .execute()
        if not domain_row.data:
            raise HTTPException(404, "Domain not found")
        domain_name = domain_row.data[0]["domain"]
    else:
        domain_name = body.domain or "your domains"

    meta = {
        "user_id":   str(user["sub"]),
        "domain_id": str(body.domain_id or ""),
        "domain":    domain_name,
        "plan":      body.plan,
    }

    try:
        if body.plan == "scan":
            # $5/scan — one-time per domain
            price_id = os.getenv("STRIPE_SCAN_PRICE_ID", "")
            session = _get_stripe().checkout.Session.create(
                payment_method_types=["card"],
                mode="payment",
                line_items=[{"price": price_id, "quantity": 1}] if price_id else [{
                    "price_data": {
                        "currency": "usd",
                        "unit_amount": 500,     # $5.00
                        "product_data": {
                            "name": f"Security Scan — {domain_name}",
                            "description": "Full 22-check security scan with AI analysis. One-time payment.",
                        },
                    },
                    "quantity": 1,
                }],
                success_url=f"{FRONTEND_URL}?payment=success&domain_id={body.domain_id}",
                cancel_url=f"{FRONTEND_URL}?payment=cancelled",
                metadata=meta,
                customer_email=user_email,
            )
        elif body.plan == "professional":
            # $588/year (= $49/mo billed annually), up to 10 domains
            price_id = os.getenv("STRIPE_PROFESSIONAL_PRICE_ID", "")
            line_items = [{"price": price_id, "quantity": 1}] if price_id else [{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 58800,   # $588.00/year
                    "recurring": {"interval": "year"},
                    "product_data": {
                        "name": "SwarmHawk Professional — Annual Plan",
                        "description": "Up to 10 domains, 10 scans per domain per year. Billed annually.",
                    },
                },
                "quantity": 1,
            }]
            session = _get_stripe().checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",
                line_items=line_items,
                success_url=f"{FRONTEND_URL}?payment=success&plan=professional",
                cancel_url=f"{FRONTEND_URL}?payment=cancelled",
                metadata=meta,
                customer_email=user_email,
                subscription_data={"metadata": meta},
            )
        elif body.plan == "one_time":
            # Legacy: $10 one-time
            session = _get_stripe().checkout.Session.create(
                payment_method_types=["card"],
                mode="payment",
                line_items=[{
                    "price_data": {
                        "currency": "usd",
                        "unit_amount": 1000,
                        "product_data": {
                            "name": f"Security Report — {domain_name}",
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
        else:  # annual — legacy $50/year
            annual_price_id = os.getenv("STRIPE_ANNUAL_PRICE_ID", "")
            line_items = [{"price": annual_price_id, "quantity": 1}] if annual_price_id else [{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 5000,
                    "recurring": {"interval": "year"},
                    "product_data": {"name": "SwarmHawk Annual — Security Monitoring"},
                },
                "quantity": 1,
            }]
            session = _get_stripe().checkout.Session.create(
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

    except _get_stripe().error.StripeError as e:
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
        event = _get_stripe().Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except _get_stripe().error.SignatureVerificationError:
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
                        .eq("user_id", p["user_id"]).is_("revoked_at", "null").execute()
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
    import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
                "resultsPerPage": 10,
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
                    if score and score >= 7.0 and score > best_score:
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
    """Return key row for a valid API key. Raises 401/429 on failure."""
    if not api_key:
        raise HTTPException(401, "Missing X-API-Key header")
    import hashlib as _hl
    key_hash = _hl.sha256(api_key.encode()).hexdigest()
    db = get_db()
    row = db.table("api_keys").select("id, user_id, calls_this_month, limit_per_month, revoked_at")\
        .eq("key_hash", key_hash).execute()
    if not row.data:
        raise HTTPException(401, "Invalid API key")
    r = row.data[0]
    if r.get("revoked_at"):
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
        db.table("api_keys").update({
            "calls_this_month": (user.get("calls_this_month") or 0) + 1,
            "last_used_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", user["id"]).execute()
    elif auth_hdr.startswith("Bearer "):
        # Session-authenticated dashboard user
        user = get_user_from_header(auth_hdr)
        # If this session user also has an API key, enforce the same quota
        _uid = user.get("sub")
        if _uid:
            _key_row = db.table("api_keys").select("id, user_id, calls_this_month, limit_per_month, revoked_at")\
                .eq("user_id", _uid).is_("revoked_at", "null").execute()
            if _key_row.data:
                _kr = _key_row.data[0]
                _limit = _kr.get("limit_per_month") or 10
                _used  = _kr.get("calls_this_month") or 0
                if _used >= _limit:
                    raise HTTPException(429, f"Monthly API limit reached ({_limit} calls). Upgrade at swarmhawk.com")
                db.table("api_keys").update({
                    "calls_this_month": _used + 1,
                    "last_used_at": datetime.now(timezone.utc).isoformat(),
                }).eq("id", _kr["id"]).execute()
    else:
        raise HTTPException(401, "Missing X-API-Key header or Authorization token")

    body    = await request.json()
    domain  = (body.get("domain") or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")
    import re as _re
    if not _re.match(r'^[a-z0-9][a-z0-9\-\.]{1,253}[a-z0-9]$', domain):
        raise HTTPException(400, "Invalid domain format")

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
    """Generate a new API key. Returns existing active key if one already exists."""
    user = get_user_from_header(authorization)
    db   = get_db()
    try:
        existing = db.table("api_keys")\
            .select("id,key_prefix,calls_this_month,limit_per_month,created_at")\
            .eq("user_id", user["sub"]).is_("revoked_at", "null").execute()
        if existing.data:
            k = existing.data[0]
            return {"keys": [k], "created": False, "full_key": None}
        import hashlib as _hl
        raw_key   = "swh_" + secrets.token_hex(24)
        key_hash  = _hl.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:12]
        res = db.table("api_keys").insert({
            "user_id":          user["sub"],
            "key_hash":         key_hash,
            "key_prefix":       key_prefix,
            "name":             "Default",
            "calls_this_month": 0,
            "limit_per_month":  10,
            "created_at":       datetime.now(timezone.utc).isoformat(),
        }).execute()
        if not res.data:
            raise HTTPException(500, "Insert returned no data — ensure SUPABASE_SERVICE_KEY is set in Render")
        new_id = res.data[0]["id"]
        return {
            "keys":     [{"id": new_id, "key_prefix": key_prefix, "calls_this_month": 0, "limit_per_month": 10}],
            "created":  True,
            "full_key": raw_key,   # shown once — never stored in plaintext
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to create API key: {str(e)[:300]}")


@app.get("/api/v1/keys")
def list_api_keys(authorization: str = Header(None)):
    """List active API keys and usage for the current user."""
    user = get_user_from_header(authorization)
    db   = get_db()
    rows = db.table("api_keys")\
        .select("id,key_prefix,calls_this_month,limit_per_month,last_used_at,created_at")\
        .eq("user_id", user["sub"]).is_("revoked_at", "null").execute()
    return {"keys": rows.data or []}


@app.post("/api/v1/keys/{key_id}/regenerate")
def regenerate_api_key(key_id: str, authorization: str = Header(None)):
    """Revoke the given key and issue a fresh one, preserving the usage limit."""
    user = get_user_from_header(authorization)
    db   = get_db()
    existing = db.table("api_keys").select("id,limit_per_month,name")\
        .eq("id", key_id).eq("user_id", user["sub"]).is_("revoked_at", "null").execute()
    if not existing.data:
        raise HTTPException(404, "Key not found")
    limit = existing.data[0].get("limit_per_month") or 10
    name  = existing.data[0].get("name") or "Default"
    # Revoke old key
    db.table("api_keys").update({"revoked_at": datetime.now(timezone.utc).isoformat()})\
        .eq("id", key_id).execute()
    # Issue new key
    import hashlib as _hl
    raw_key    = "swh_" + secrets.token_hex(24)
    key_hash   = _hl.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]
    res = db.table("api_keys").insert({
        "user_id":          user["sub"],
        "key_hash":         key_hash,
        "key_prefix":       key_prefix,
        "name":             name,
        "calls_this_month": 0,
        "limit_per_month":  limit,
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }).execute()
    new_id = res.data[0]["id"] if res.data else None
    return {"id": new_id, "key_prefix": key_prefix, "full_key": raw_key, "calls_this_month": 0, "limit_per_month": limit}


@app.delete("/api/v1/keys/{key_id}")
def revoke_api_key(key_id: str, authorization: str = Header(None)):
    """Soft-revoke an API key."""
    user = get_user_from_header(authorization)
    db   = get_db()
    db.table("api_keys").update({"revoked_at": datetime.now(timezone.utc).isoformat()})\
        .eq("id", key_id).eq("user_id", user["sub"]).execute()
    return {"revoked": key_id}


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
        session = _get_stripe().checkout.Session.create(**create_kwargs)
        return {"url": session.url}
    except _get_stripe().error.StripeError as e:
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
        .eq("user_id", user_id).is_("revoked_at", "null").execute()
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
    # Only use a preconfigured price ID if it looks like a real Stripe ID (min ~20 chars)
    if price_id and len(price_id) >= 20:
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
        session = _get_stripe().checkout.Session.create(
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
    except _get_stripe().error.StripeError as e:
        raise HTTPException(400, str(e))


@app.get("/api/v1/plan")
def get_api_plan(authorization: str = Header(None)):
    """Return the current API pricing plan and usage for the authenticated user."""
    user = get_user_from_header(authorization)
    db   = get_db()
    plan_info = _get_user_api_plan(db, user["sub"])
    # Enrich with actual usage from the user's active API keys
    keys = db.table("api_keys").select("calls_this_month,limit_per_month")\
        .eq("user_id", user["sub"]).is_("revoked_at", "null").execute()
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
_MAP_CACHE_TTL = 900  # 15 minutes — refresh faster as worker scans more
_dc_cache:  dict = {"data": None, "built_at": None}  # datacenter-level geo cache


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

    # ── Overlay: real scan results — scan_results (primary) + outreach_prospects (fallback) ──
    def _merge_scan_rows(rows_data, scan_counts):
        for r in (rows_data or []):
            cc = (r.get("country") or "").upper().strip()
            if not cc or cc in ("EU", "??", ""):
                cc = tld_to_country(r.get("domain", "unknown.com"))
            if not cc:
                cc = "US"  # default undetectable TLDs (.com/.net/.org etc.) to US
            if cc not in scan_counts:
                scan_counts[cc] = {"domains": 0, "scanned": 0, "risk_scores": []}
            scan_counts[cc]["domains"] += 1
            if r.get("last_scanned_at") or r.get("scanned_at"):
                scan_counts[cc]["scanned"] += 1
            # Prefer risk_score (enrichment-aware); fall back to max_cvss × 10
            risk = r.get("risk_score")
            if risk is None:
                cvss = r.get("max_cvss")
                risk = float(cvss) * 10 if cvss is not None else None
            if risk is not None:
                try:
                    scan_counts[cc]["risk_scores"].append(float(risk))
                except (ValueError, TypeError):
                    pass

    scan_counts: dict = {}

    # Primary source: unified scan_results table (all tiers)
    sr_rows_data = []
    try:
        sr_rows = db.table("scan_results")\
            .select("domain,country,risk_score,max_cvss,last_scanned_at")\
            .execute()
        sr_rows_data = sr_rows.data or []
        _merge_scan_rows(sr_rows_data, scan_counts)
    except Exception as e:
        print(f"[map] scan_results query failed: {e}")

    # Fallback/supplement: outreach_prospects (for data not yet in scan_results)
    try:
        op_rows = db.table("outreach_prospects")\
            .select("domain,country,max_cvss,scanned_at")\
            .execute()
        sr_domains = {r.get("domain") for r in sr_rows_data}
        filtered = [r for r in (op_rows.data or []) if r.get("domain") not in sr_domains]
        _merge_scan_rows(filtered, scan_counts)
    except Exception as e:
        print(f"[map] outreach_prospects query failed: {e}")

    # User-added domains: domains table joined with latest scan score
    try:
        user_doms = db.table("domains")\
            .select("domain,country,scans(risk_score,scanned_at)")\
            .execute()
        all_seen = {r.get("domain") for r in sr_rows_data}
        user_rows = []
        for d in (user_doms.data or []):
            dom = d.get("domain", "")
            if dom in all_seen:
                continue  # already counted from scan_results
            scans = d.get("scans") or []
            latest = max(scans, key=lambda s: s.get("scanned_at") or "", default=None) if scans else None
            user_rows.append({
                "domain":          dom,
                "country":         d.get("country"),
                "risk_score":      latest["risk_score"] if latest else None,
                "last_scanned_at": latest["scanned_at"] if latest else None,
            })
        _merge_scan_rows(user_rows, scan_counts)
    except Exception as e:
        print(f"[map] user domains query failed: {e}")

    for cc, sc in scan_counts.items():
        if cc not in country_data:
            country_data[cc] = {
                "country": cc, "domains": 0, "scanned": 0,
                "avg_risk": 0, "high_risk_domains": 0, "critical_findings": 0,
                "_cvss_sum": 0.0, "_cvss_count": 0,
            }
        country_data[cc]["domains"]  = max(country_data[cc]["domains"], sc["domains"])
        country_data[cc]["scanned"]  = sc["scanned"]
        scores = sc["risk_scores"]
        if scores:
            country_data[cc]["avg_risk"]          = round(sum(scores) / len(scores), 1)
            country_data[cc]["high_risk_domains"] = sum(1 for s in scores if s >= 60)
            country_data[cc]["critical_findings"] = sum(1 for s in scores if s >= 80)

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
        "last_updated":  now,
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


@app.get("/map/datacenters")
def map_datacenters():
    """
    Public: domain points with city/datacenter-level geo coordinates.
    Returns only domains that have been geo-enriched (ip_lat != null).
    Cached 30 minutes. Used by map.html at zoom >= 5.
    """
    global _dc_cache
    now = datetime.now(timezone.utc)
    if _dc_cache["data"] is not None and _dc_cache.get("built_at"):
        age = (now - _dc_cache["built_at"]).total_seconds()
        if age < 1800:
            return _dc_cache["data"]

    try:
        from outreach import get_db as outreach_get_db
        db = outreach_get_db()
        rows = db.table("scan_results")\
            .select("domain,ip_lat,ip_lon,ip_city,ip_asn,ip_org,risk_score,country")\
            .not_.is_("ip_lat", "null")\
            .not_.is_("ip_lon", "null")\
            .execute()
        points = []
        for r in (rows.data or []):
            lat = r.get("ip_lat")
            lon = r.get("ip_lon")
            if lat is None or lon is None:
                continue
            points.append({
                "domain":    r.get("domain", ""),
                "lat":       round(float(lat), 4),
                "lon":       round(float(lon), 4),
                "city":      r.get("ip_city") or "",
                "asn":       r.get("ip_asn") or "",
                "org":       r.get("ip_org") or "",
                "risk":      r.get("risk_score") or 0,
                "country":   r.get("country") or "",
            })
        result = {"points": points, "total": len(points)}
        _dc_cache["data"]     = result
        _dc_cache["built_at"] = now
        return result
    except Exception as e:
        return {"points": [], "total": 0, "error": str(e)}


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

        # ── 1. Primary: scan_results — ALL scanned domains, any CVSS ────────────
        sr_rows = db.table("scan_results")\
            .select("domain,country,risk_score,max_cvss,last_scanned_at,scan_tier,source")\
            .not_.is_("last_scanned_at", "null")\
            .execute()

        for r in (sr_rows.data or []):
            dom = r.get("domain", "")
            cc = (r.get("country") or "").upper().strip()
            if not cc or cc in ("EU", "??", ""):
                cc = tld_to_country(dom) or "US"
            if cc != code:
                continue
            if dom in seen:
                continue
            seen.add(dom)
            risk_score = r.get("risk_score") or 0
            domain_rows.append({
                "domain":     dom,
                "risk_score": risk_score,
                "scanned_at": fmt_date(r.get("last_scanned_at")),
                "max_cvss":   round(float(r.get("max_cvss") or 0), 1),
                "source":     r.get("source") or "pipeline",
                "tier":       r.get("scan_tier", 1),
            })

        # ── 2. Supplement: outreach_prospects (legacy, not yet in scan_results) ─
        all_prospects = db.table("outreach_prospects")\
            .select("domain,country,max_cvss,scanned_at")\
            .not_.is_("scanned_at", "null")\
            .execute()

        for r in (all_prospects.data or []):
            dom = r.get("domain", "")
            if dom in seen:
                continue
            cc = (r.get("country") or "").upper().strip()
            if not cc or cc in ("EU", "??", ""):
                cc = tld_to_country(dom)
            if cc != code:
                continue
            seen.add(dom)
            cvss = r.get("max_cvss") or 0
            risk_score = min(100, int(round(cvss * 10)))
            domain_rows.append({
                "domain":     dom,
                "risk_score": risk_score,
                "scanned_at": fmt_date(r.get("scanned_at")),
                "max_cvss":   round(cvss, 1),
                "source":     "outreach",
            })

        # ── 3. Supplement: domain_queue — discovered but not yet scanned ─────
        try:
            dq_rows = db.table("domain_queue")\
                .select("domain,country,added_at")\
                .execute()
            for r in (dq_rows.data or []):
                dom = r.get("domain", "")
                if dom in seen:
                    continue
                cc = (r.get("country") or "").upper().strip()
                if not cc or cc in ("EU", "??", ""):
                    cc = tld_to_country(dom)
                if cc != code:
                    continue
                seen.add(dom)
                domain_rows.append({
                    "domain":     dom,
                    "risk_score": 0,
                    "scanned_at": "",
                    "max_cvss":   0.0,
                    "source":     "queued",
                    "status":     "pending scan",
                })
        except Exception:
            pass

        # Total discovered (before limiting)
        total_discovered = len(domain_rows)
        scanned_rows = [d for d in domain_rows if d.get("scanned_at")]
        scanned_count = len(scanned_rows)

        # Sort: scanned first (by risk desc), then queued at bottom
        domain_rows.sort(key=lambda x: (1 if x.get("scanned_at") else 0, x["risk_score"]), reverse=True)
        domain_rows = domain_rows[:500]

        high_risk = sum(1 for d in domain_rows if d["risk_score"] >= 70)
        avg_risk = int(sum(d["risk_score"] for d in scanned_rows) / scanned_count) if scanned_count else 0
        summary = {
            "total_tracked": total_discovered,
            "scanned":       scanned_count,
            "avg_risk":      avg_risk,
            "high_risk":     high_risk,
        }

    except Exception as exc:
        summary = {"error": str(exc)}

    return {"country": code, "domains": domain_rows, "total": len(domain_rows), "summary": summary}


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL PIPELINE — status and admin endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/pipeline/status")
def pipeline_status():
    """Public: live statistics for the global domain security pipeline."""
    try:
        from pipeline import get_pipeline_status
        return get_pipeline_status()
    except Exception as e:
        return {"error": str(e)}


@app.get("/outreach/funnel")
def outreach_funnel(authorization: str = Header(None)):
    """Admin: outreach pipeline funnel — shows where prospects drop off."""
    require_admin(authorization)
    db = get_admin_db()
    try:
        sr = db.table("scan_results")
        total_scanned   = sr.select("id", count="exact").not_.is_("last_scanned_at", "null").execute().count or 0
        qualified       = sr.select("id", count="exact").not_.is_("outreach_status", "null").execute().count or 0
        pending         = sr.select("id", count="exact").eq("outreach_status", "pending").execute().count or 0
        has_email       = sr.select("id", count="exact").eq("outreach_status", "pending").not_.eq("contact_email", "").execute().count or 0
        approved        = sr.select("id", count="exact").eq("outreach_status", "approved").execute().count or 0
        sent            = sr.select("id", count="exact").eq("outreach_status", "sent").execute().count or 0
        skipped         = sr.select("id", count="exact").eq("outreach_status", "skipped").execute().count or 0
        # Qualification breakdown
        missing_dmarc   = sr.select("id", count="exact").eq("dmarc_status", "missing").is_("outreach_status", "null").execute().count or 0
        missing_spf     = sr.select("id", count="exact").eq("spf_status", "missing").is_("outreach_status", "null").execute().count or 0
        blacklisted     = sr.select("id", count="exact").eq("blacklisted", True).is_("outreach_status", "null").execute().count or 0
        return {
            "funnel": {
                "total_scanned":  total_scanned,
                "qualified":      qualified,
                "pending":        pending,
                "has_email":      has_email,
                "approved":       approved,
                "sent":           sent,
                "skipped":        skipped,
            },
            "unqualified_gaps": {
                "missing_dmarc_not_yet_qualified": missing_dmarc,
                "missing_spf_not_yet_qualified":   missing_spf,
                "blacklisted_not_yet_qualified":   blacklisted,
            },
            "tip": "Run POST /pipeline/backfill-outreach to qualify all existing domains",
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/pipeline/run-discovery")
def pipeline_run_discovery(authorization: str = Header(None)):
    """Admin: manually trigger global domain discovery (Cloudflare Radar + CT logs)."""
    require_admin(authorization)
    try:
        from pipeline import run_discovery_job
        import threading
        threading.Thread(target=run_discovery_job, daemon=True).start()
        return {"status": "discovery started"}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/pipeline/run-tier1")
def pipeline_run_tier1(authorization: str = Header(None), batch_size: int = 0):
    """Admin: manually trigger Tier 1 batch scan of queued domains.

    batch_size: override default batch size (0 = use default from env/config)
    """
    require_admin(authorization)
    try:
        from pipeline import run_tier1_batch
        import threading
        kwargs = {"batch_size": batch_size} if batch_size > 0 else {}
        threading.Thread(target=run_tier1_batch, kwargs=kwargs, daemon=True).start()
        return {"status": "tier1 batch started", "batch_size": batch_size or "default"}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/pipeline/run-tier2")
def pipeline_run_tier2(authorization: str = Header(None)):
    """Admin: manually trigger weekly Tier 2 enrichment scan."""
    require_admin(authorization)
    try:
        from pipeline import run_enrichment_weekly
        import threading
        threading.Thread(target=run_enrichment_weekly, daemon=True).start()
        return {"status": "tier2 enrichment started"}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/admin/batch-upload")
async def admin_batch_upload(
    authorization: str = Header(None),
    file: UploadFile = File(...),
):
    """Admin: upload a .txt or .json file of domains to inject into the pipeline queue.

    .txt  — one domain per line (blank lines and # comments ignored)
    .json — JSON array of strings  ["example.com", ...]
          OR array of objects      [{"domain": "example.com"}, ...]

    Domains are queued at priority 1 (highest) with source='batch_upload'.
    Returns {total_submitted, queued, duplicates_skipped, invalid, sample_invalid}.
    """
    require_admin(authorization)

    content = await file.read()
    filename = (file.filename or "").lower()

    raw_domains: list[str] = []

    if filename.endswith(".json"):
        try:
            data = json.loads(content.decode("utf-8", errors="replace"))
            if not isinstance(data, list):
                raise HTTPException(400, "JSON must be a top-level array")
            for item in data:
                if isinstance(item, str):
                    raw_domains.append(item.strip())
                elif isinstance(item, dict):
                    d = item.get("domain") or item.get("Domain") or item.get("url") or ""
                    if d:
                        raw_domains.append(str(d).strip())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(400, f"Invalid JSON: {exc}")

    elif filename.endswith(".txt"):
        for line in content.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw_domains.append(line)
    else:
        raise HTTPException(400, "Only .txt and .json files are supported")

    if not raw_domains:
        raise HTTPException(400, "No domains found in file")

    total_submitted = len(raw_domains)

    # Validate format before handing to ingest_domains
    _domain_re = re.compile(r'^[a-z0-9][a-z0-9\-\.]{1,253}[a-z0-9]$')
    valid, invalid = [], []
    for d in raw_domains:
        d = d.lower().strip().rstrip(".")
        # Strip http(s):// scheme if accidentally included
        for prefix in ("https://", "http://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
        d = d.split("/")[0]  # strip any path
        if d and _domain_re.match(d) and "." in d:
            valid.append(d)
        else:
            invalid.append(d)

    sample_invalid = invalid[:10]

    from pipeline import ingest_domains as _ingest
    db = get_db()

    # Count what's already in scan_results (duplicates)
    already_scanned: set[str] = set()
    for i in range(0, len(valid), 500):
        chunk = valid[i:i + 500]
        try:
            rows = db.table("scan_results").select("domain").in_("domain", chunk).execute().data or []
            already_scanned.update(r["domain"] for r in rows)
        except Exception:
            pass

    queued = _ingest(valid, source="batch_upload", db=db, skip_scan_check=False)
    duplicates_skipped = len(already_scanned)

    log.info(
        f"[batch_upload] total={total_submitted} valid={len(valid)} "
        f"queued={queued} dupes={duplicates_skipped} invalid={len(invalid)}"
    )

    return {
        "total_submitted":   total_submitted,
        "valid":             len(valid),
        "queued":            queued,
        "duplicates_skipped": duplicates_skipped,
        "invalid":           len(invalid),
        "sample_invalid":    sample_invalid,
    }


@app.post("/pipeline/run-bulk-discovery")
def pipeline_run_bulk_discovery(authorization: str = Header(None)):
    """Admin: manually trigger weekly bulk discovery (Tranco + Umbrella ~2M domains)."""
    require_admin(authorization)
    try:
        from pipeline import run_bulk_discovery_job
        import threading
        threading.Thread(target=run_bulk_discovery_job, daemon=True).start()
        return {"status": "bulk discovery started (Tranco + Umbrella)"}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/pipeline/backfill-outreach")
def pipeline_backfill_outreach(authorization: str = Header(None)):
    """Admin: mark already-scanned domains as pending outreach if they qualify.
    Qualification: max_cvss >= 7 OR risk_score >= 40 OR missing DMARC/SPF OR blacklisted.
    Safe to run multiple times — only touches rows where outreach_status IS NULL."""
    require_admin(authorization)
    db = get_admin_db()
    from pipeline import _domain_qualifies
    try:
        updated = 0
        offset  = 0
        chunk   = 500
        while True:
            rows = db.table("scan_results")\
                .select("id,max_cvss,risk_score,dmarc_status,spf_status,blacklisted")\
                .is_("outreach_status", "null")\
                .range(offset, offset + chunk - 1)\
                .execute()
            if not rows.data:
                break
            qualifying = [
                r["id"] for r in rows.data
                if _domain_qualifies(
                    float(r.get("max_cvss") or 0),
                    int(r.get("risk_score") or 0),
                    r,
                )
            ]
            if qualifying:
                db.table("scan_results")\
                    .update({"outreach_status": "pending"})\
                    .in_("id", qualifying)\
                    .execute()
                updated += len(qualifying)
            offset += chunk
            if len(rows.data) < chunk:
                break
        # Also dual-write the newly-marked + existing pending rows to outreach_prospects
        from pipeline import backfill_outreach_prospects
        written = backfill_outreach_prospects(db=db)
        return {
            "backfilled":           updated,
            "prospects_written":    written,
            "message": f"{updated} domains marked pending in scan_results, {written} written to outreach_prospects",
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/pipeline/run-sonar-import")
def pipeline_run_sonar_import(
    authorization: str = Header(None),
    source: str = "https",
    limit: int = 500000,
    tlds: str = "",
):
    """Admin: stream Rapid7 Project Sonar dump and bulk-upsert into scan_results.

    source: 'https' (TLS cert scans) or 'fdns' (forward DNS A records)
    limit:  max domains to import (default 500 000)
    tlds:   comma-separated TLD filter, e.g. 'cz,de,pl' (empty = all TLDs)
    """
    require_admin(authorization)
    import threading

    def _run():
        try:
            import sys
            import os as _os
            # sonar_import lives alongside main.py
            sys.path.insert(0, _os.path.dirname(__file__))
            import sonar_import
            tld_filter = set(tlds.lower().split(",")) - {""} if tlds else None
            file_url = sonar_import.get_latest_file_url(source)
            stream_fn = sonar_import.stream_sonar_https if source == "https" else sonar_import.stream_sonar_fdns
            db = sonar_import.get_db()
            batch, total = [], 0
            for rec in stream_fn(file_url, tld_filter, limit):
                batch.append(sonar_import._make_row(rec))
                if len(batch) >= sonar_import.BATCH_SIZE:
                    total += sonar_import.upsert_batch(db, batch, dry_run=False)
                    batch = []
            if batch:
                total += sonar_import.upsert_batch(db, batch, dry_run=False)
            print(f"[sonar-import] Done — {total:,} domains upserted from Rapid7 {source}")
        except Exception as exc:
            print(f"[sonar-import] ERROR: {exc}")

    threading.Thread(target=_run, daemon=True).start()
    return {"status": f"sonar import started (source={source}, limit={limit}, tlds='{tlds or 'all'}')"}


# ══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE — Organization Graph + Breach Path + CTEM
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/enterprise/stats")
def enterprise_stats(authorization: str = Header(None)):
    """Enterprise-wide stats: orgs, entry points, breach paths, choke points."""
    get_user_from_header(authorization)
    db = get_db()
    try:
        orgs = db.table("organizations").select("org_risk_score,entry_points,critical_assets,choke_points,attack_paths,domain_count", count="exact").execute()
        total_orgs  = orgs.count or 0
        rows        = orgs.data or []
        total_entry = sum(r.get("entry_points", 0) for r in rows)
        total_crit  = sum(r.get("critical_assets", 0) for r in rows)
        total_paths = sum(r.get("attack_paths", 0) for r in rows)
        total_choke = sum(r.get("choke_points", 0) for r in rows)
        total_doms  = sum(r.get("domain_count", 0) for r in rows)
        avg_risk    = round(sum(r.get("org_risk_score", 0) for r in rows) / max(total_orgs, 1))
        pipeline    = db.table("scan_results").select("id", count="exact").execute()
        return {
            "total_organizations":  total_orgs,
            "total_domains_mapped": total_doms,
            "total_entry_points":   total_entry,
            "total_critical_assets":total_crit,
            "total_attack_paths":   total_paths,
            "total_choke_points":   total_choke,
            "avg_org_risk_score":   avg_risk,
            "total_scan_results":   pipeline.count or 0,
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/enterprise/orgs")
def enterprise_list_orgs(
    authorization: str = Header(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    sort: str = Query("risk"),          # risk | domains | paths | name
    min_risk: int = Query(0, ge=0),
    country: str = Query(None),
):
    """List organizations sorted by risk score, domain count, or attack paths."""
    get_user_from_header(authorization)
    db = get_db()
    try:
        q = db.table("organizations").select(
            "id,registered_domain,name,domain_count,org_risk_score,"
            "entry_points,critical_assets,choke_points,attack_paths,country,last_computed"
        ).gte("org_risk_score", min_risk)
        if country:
            q = q.eq("country", country)
        col = {"risk": "org_risk_score", "domains": "domain_count",
               "paths": "attack_paths", "name": "registered_domain"}.get(sort, "org_risk_score")
        q = q.order(col, desc=(sort != "name"))
        offset = (page - 1) * limit
        rows = q.range(offset, offset + limit - 1).execute().data or []
        total = db.table("organizations").select("id", count="exact").gte("org_risk_score", min_risk).execute().count or 0
        return {"organizations": rows, "total": total, "page": page, "limit": limit}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/enterprise/orgs/{org_id}")
def enterprise_get_org(org_id: str, authorization: str = Header(None)):
    """Full organization detail including asset_graph (nodes, edges, paths, choke_points)."""
    get_user_from_header(authorization)
    db = get_db()
    row = db.table("organizations").select("*").eq("id", org_id).execute()
    if not row.data:
        raise HTTPException(404, "Organization not found")
    org = row.data[0]
    # Also fetch the individual domain records for this org
    domains = db.table("scan_results").select(
        "domain,risk_score,max_cvss,scan_tier,priority,blacklisted,"
        "spf_status,dmarc_status,waf_detected,ip_reputation,last_scanned_at"
    ).eq("registered_domain", org["registered_domain"]).order("risk_score", desc=True).limit(100).execute().data or []
    org["domains"] = domains
    return org


@app.post("/enterprise/orgs/{org_id}/recompute")
def enterprise_recompute_org(org_id: str, authorization: str = Header(None)):
    """Recompute breach paths for a single organization."""
    require_admin(authorization)
    try:
        from org_graph import compute_org_graph_job
        import threading
        threading.Thread(target=compute_org_graph_job, kwargs={"org_id": org_id}, daemon=True).start()
        return {"status": "recompute started", "org_id": org_id}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/enterprise/compute")
def enterprise_compute_all(authorization: str = Header(None)):
    """Admin: run full org clustering + breach path computation across all scan_results."""
    require_admin(authorization)
    try:
        from org_graph import compute_org_graph_job
        import threading
        threading.Thread(target=compute_org_graph_job, daemon=True).start()
        return {"status": "full org graph computation started"}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/enterprise/breach-paths")
def enterprise_breach_paths(
    authorization: str = Header(None),
    min_paths: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """List organizations with the most breach paths — highest priority targets."""
    get_user_from_header(authorization)
    db = get_db()
    try:
        rows = db.table("organizations").select(
            "id,registered_domain,name,org_risk_score,attack_paths,choke_points,entry_points,critical_assets,country"
        ).gte("attack_paths", min_paths).order("attack_paths", desc=True).limit(limit).execute().data or []
        return {"organizations": rows}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/enterprise/orgs/by-domain/{domain}")
def enterprise_org_by_domain(domain: str, authorization: str = Header(None)):
    """Look up which organization a domain belongs to."""
    get_user_from_header(authorization)
    db = get_db()
    sr = db.table("scan_results").select("registered_domain").eq("domain", domain.lower()).execute()
    if not sr.data or not sr.data[0].get("registered_domain"):
        raise HTTPException(404, "Domain not found or not yet tagged with organization")
    reg = sr.data[0]["registered_domain"]
    org = db.table("organizations").select("*").eq("registered_domain", reg).execute()
    if not org.data:
        raise HTTPException(404, "Organization not yet computed for this domain")
    return org.data[0]


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


# (Deep Scan removed — functionality folded into regular scan)


# ══════════════════════════════════════════════════════════════════════════════
# API v2 — Clean Public API
#
# Authentication: X-API-Key header OR Authorization: Bearer <session_token>
# Docs: https://www.swarmhawk.com/docs/api
# ══════════════════════════════════════════════════════════════════════════════

_v2 = APIRouter(prefix="/api/v2", tags=["API v2"])

@_v2.post("/scan",    summary="Trigger a domain scan")
async def v2_scan(request: Request, background_tasks: BackgroundTasks):
    return await api_scan(request, background_tasks)

@_v2.get("/domains",  summary="List domains")
def v2_list_domains(authorization: str = Header(None)):
    return list_domains(authorization)

@_v2.post("/domains", summary="Add a domain")
def v2_add_domain(body: AddDomainRequest, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    return add_domain(body, background_tasks, authorization)

@_v2.delete("/domains/{domain_id}", summary="Remove a domain")
def v2_delete_domain(domain_id: str, authorization: str = Header(None)):
    return delete_domain(domain_id, authorization)

@_v2.post("/domains/{domain_id}/rescan", summary="Re-trigger scan")
def v2_rescan_domain(domain_id: str, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    return rescan_domain(domain_id, background_tasks, authorization)

@_v2.get("/domains/{domain_id}/report", summary="Get latest scan report")
def v2_get_report(domain_id: str, authorization: str = Header(None)):
    return get_report(domain_id, authorization)

@_v2.get("/domains/{domain_id}/history", summary="Get scan history")
def v2_get_domain_history(domain_id: str, authorization: str = Header(None)):
    return get_domain_history(domain_id, authorization)

@_v2.get("/domains/{domain_id}/nis2", summary="Get NIS2 compliance status")
def v2_get_nis2_compliance(domain_id: str, authorization: str = Header(None)):
    return get_nis2_compliance(domain_id, authorization)

@_v2.post("/keys", summary="Create an API key")
def v2_create_api_key(authorization: str = Header(None)):
    return create_api_key(authorization)

@_v2.get("/keys", summary="List API keys and usage")
def v2_list_api_keys(authorization: str = Header(None)):
    return list_api_keys(authorization)

@_v2.post("/keys/{key_id}/regenerate", summary="Regenerate an API key")
def v2_regenerate_api_key(key_id: str, authorization: str = Header(None)):
    return regenerate_api_key(key_id, authorization)

@_v2.delete("/keys/{key_id}", summary="Revoke an API key")
def v2_revoke_api_key(key_id: str, authorization: str = Header(None)):
    return revoke_api_key(key_id, authorization)

@_v2.get("/me", summary="Get current user profile")
def v2_get_me(authorization: str = Header(None)):
    return get_me(authorization)

@_v2.get("/plan", summary="Get API plan and usage")
def v2_get_api_plan(authorization: str = Header(None)):
    return get_api_plan(authorization)

app.include_router(_v2)


# ══════════════════════════════════════════════════════════════════════════════
# PLANS CATALOG
# ══════════════════════════════════════════════════════════════════════════════

PLANS = [
    {
        "id":           "free",
        "name":         "Free",
        "price_usd":    0,
        "period":       None,
        "billing":      None,
        "domain_limit": 1,
        "scan_limit":   1,
        "api_access":   False,
        "bulk_upload":  False,
        "features": [
            "1 domain",
            "1 full security scan — free",
            "Additional scans — $5/scan",
            "Risk score dashboard",
            "Basic PDF report",
        ],
        "cta_label": "Get Started Free",
        "checkout_url": None,
    },
    {
        "id":           "professional",
        "name":         "Professional",
        "price_usd":    49,
        "period":       "mo",
        "billing":      "yearly",
        "annual_total": 588,
        "domain_limit": 10,
        "scan_limit":   10,
        "api_access":   True,
        "bulk_upload":  True,
        "features": [
            "2–10 domains",
            "10 scans per domain per year",
            "22-check full scan engine",
            "Risk dashboard & email alerts",
            "PDF report + email delivery",
            "Bulk domain upload",
            "Priority support",
        ],
        "cta_label": "Upgrade to Professional",
        "checkout_url": None,
    },
    {
        "id":           "platform",
        "name":         "Platform",
        "price_usd":    None,
        "period":       None,
        "billing":      None,
        "domain_limit": None,
        "scan_limit":   None,
        "api_access":   True,
        "bulk_upload":  True,
        "features": [
            "Unlimited domains",
            "Pay per request / domain scan",
            "Custom scan volume & pricing",
            "White-label dashboard",
            "API integration & webhooks",
            "Dedicated account manager",
            "Custom SLA",
        ],
        "cta_label": "Talk to Sales",
        "checkout_url": None,
    },
]


@app.get("/plans")
def list_plans():
    """Public: return all available plans and their features."""
    return {"plans": PLANS}


@app.get("/me/plan")
def get_user_plan(authorization: str = Header(None)):
    """Return the current user's active plan ID and domain usage."""
    user = get_user_from_header(authorization)
    db   = get_admin_db()
    uid  = user["sub"]

    # Count owned domains
    domain_count = db.table("domains").select("id", count="exact").eq("user_id", uid).execute()
    count = domain_count.count or 0

    # Admin users get unlimited access regardless of purchases
    if is_admin(uid):
        return {
            "plan_id":      "admin",
            "plan_name":    "Admin",
            "domain_limit": None,
            "domain_count": count,
            "bulk_upload":  True,
        }

    # Check purchases to infer plan
    purchases = db.table("purchases").select("amount_usd,paid_at,plan").eq("user_id", uid)\
        .not_.is_("paid_at", "null").execute()

    # Prefer explicit plan column if present; fall back to amount heuristic
    plan_ids_paid = {p.get("plan") for p in (purchases.data or []) if p.get("plan")}
    if "professional" in plan_ids_paid or "platform" in plan_ids_paid:
        plan_id = "professional" if "platform" not in plan_ids_paid else "platform"
    elif plan_ids_paid - {"free", None}:
        # Legacy plan IDs (starter, enterprise, annual, one_time) → treat as professional
        plan_id = "professional"
    else:
        total_paid = sum(p.get("amount_usd") or 0 for p in (purchases.data or []))
        plan_id = "professional" if total_paid >= 49 else "free"

    plan = next((p for p in PLANS if p["id"] == plan_id), PLANS[0])
    return {
        "plan_id":      plan_id,
        "plan_name":    plan["name"],
        "domain_limit": plan["domain_limit"],
        "domain_count": count,
        "bulk_upload":  plan["bulk_upload"],
    }


# ══════════════════════════════════════════════════════════════════════════════
# BULK DOMAIN IMPORT (user-facing)
# ══════════════════════════════════════════════════════════════════════════════

class BulkDomainsRequest(BaseModel):
    domains: list[str]


@app.post("/domains/bulk")
async def bulk_add_domains(
    body: BulkDomainsRequest,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None),
):
    """Add multiple domains at once (JSON list). Respects plan domain limit.

    Body: {"domains": ["a.com", "b.com", ...]}
    Returns: {queued, skipped_duplicates, skipped_invalid, errors}
    """
    import re as _re
    user = get_user_from_header(authorization)
    db   = get_admin_db()
    uid  = user["sub"]

    # Determine plan limit
    user_plan = get_user_plan(f"Bearer {body.domains[0]}" if False else authorization)
    remaining = (user_plan["domain_limit"] or 999999) - user_plan["domain_count"]

    domain_re = _re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )

    queued = []
    skipped_duplicates = []
    skipped_invalid = []

    for raw in body.domains[:500]:  # hard cap per request
        domain = raw.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not domain_re.match(domain):
            skipped_invalid.append(raw)
            continue

        if len(queued) >= remaining:
            break

        # Check not already owned
        existing = db.table("domains").select("id").eq("user_id", uid).eq("domain", domain).execute()
        if existing.data:
            skipped_duplicates.append(domain)
            continue

        try:
            dom_result = db.table("domains").insert({
                "user_id":    uid,
                "domain":     domain,
                "country":    tld_to_country(domain),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
            if dom_result.data:
                d = dom_result.data[0]
                background_tasks.add_task(run_scan_background, d["id"], domain)
                queued.append(domain)
        except Exception:
            skipped_duplicates.append(domain)  # likely unique constraint

    return {
        "queued":              len(queued),
        "queued_domains":      queued,
        "skipped_duplicates":  len(skipped_duplicates),
        "skipped_invalid":     len(skipped_invalid),
        "limit_remaining":     max(0, remaining - len(queued)),
    }


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN ACTIVITY — scans-per-day for dashboard chart
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/admin/activity")
def admin_activity(days: int = 30, authorization: str = Header(None)):
    """Admin: scans per day for the last N days (default 30). For activity chart."""
    require_admin(authorization)
    db  = get_admin_db()
    from datetime import timedelta

    now    = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).isoformat()

    scans = db.table("scans").select("scanned_at").gte("scanned_at", cutoff).execute()
    users = db.table("users").select("created_at").gte("created_at", cutoff).execute()

    # Build day buckets
    buckets: dict[str, dict] = {}
    for i in range(days):
        day = (now - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        buckets[day] = {"date": day, "scans": 0, "new_users": 0}

    for s in (scans.data or []):
        day = (s.get("scanned_at") or "")[:10]
        if day in buckets:
            buckets[day]["scans"] += 1

    for u in (users.data or []):
        day = (u.get("created_at") or "")[:10]
        if day in buckets:
            buckets[day]["new_users"] += 1

    return {"activity": list(buckets.values())}


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN LOGS — recent scan events
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/admin/logs")
def admin_logs(limit: int = 100, authorization: str = Header(None)):
    """Admin: recent scan events with domain, user, risk score, timestamp."""
    require_admin(authorization)
    db = get_admin_db()

    scans = db.table("scans")\
        .select("id,domain_id,risk_score,critical,warnings,scanned_at")\
        .order("scanned_at", desc=True)\
        .limit(min(limit, 200))\
        .execute()

    # Build domain_id → domain name map
    domain_ids = list({s["domain_id"] for s in (scans.data or []) if s.get("domain_id")})
    domain_map: dict = {}
    user_map:   dict = {}

    if domain_ids:
        domains = db.table("domains").select("id,domain,user_id").in_("id", domain_ids).execute()
        for d in (domains.data or []):
            domain_map[d["id"]] = d["domain"]
            user_map[d["id"]]   = d.get("user_id", "")

    # Fetch user emails
    user_ids = list(set(user_map.values()) - {""})
    email_map: dict = {}
    if user_ids:
        users = db.table("users").select("id,email").in_("id", user_ids).execute()
        for u in (users.data or []):
            email_map[u["id"]] = u["email"]

    logs = []
    for s in (scans.data or []):
        did = s.get("domain_id", "")
        uid = user_map.get(did, "")
        logs.append({
            "scan_id":    s["id"],
            "domain":     domain_map.get(did, "—"),
            "user_email": email_map.get(uid, "—"),
            "risk_score": s.get("risk_score"),
            "critical":   s.get("critical", 0),
            "warnings":   s.get("warnings", 0),
            "scanned_at": s.get("scanned_at", ""),
        })

    return {"logs": logs, "total": len(logs)}


# ── Attack Surface / Attacker View ────────────────────────────────────────────
@app.get("/domains/{domain_id}/attack-surface")
async def get_attack_surface(domain_id: str, authorization: str = Header(None)):
    """
    Authenticated — full attack surface analysis for a domain.
    Combines Shodan port/banner/CVE data, ParanoidLab breach intel,
    existing scan results, and an AI-generated attack narrative.
    """
    import socket as _sock
    import json as _json

    user = get_user_from_header(authorization)
    db   = get_db()

    d = db.table("domains").select("id,user_id,domain").eq("id", domain_id).execute()
    if not d.data or d.data[0]["user_id"] != user["sub"]:
        raise HTTPException(403, "Not found")
    domain = d.data[0]["domain"]

    # ── Existing scan results — query scans table (same as all other endpoints) ─
    scan = db.table("scans").select(
        "risk_score,checks,scanned_at"
    ).eq("domain_id", domain_id).order("scanned_at", desc=True).limit(1).execute()
    scan_data = scan.data[0] if scan.data else {}

    raw_checks = scan_data.get("checks") or []
    if isinstance(raw_checks, str):
        try: raw_checks = _json.loads(raw_checks)
        except: raw_checks = []
    checks = raw_checks if isinstance(raw_checks, list) else []

    # Derive enrichment fields from checks array (avoids querying scan_results separately)
    check_map_quick = {c.get("check"): c for c in checks if isinstance(c, dict)}
    _spf_status   = check_map_quick.get("spf",   {}).get("status", "unknown")
    _dmarc_status = check_map_quick.get("dmarc", {}).get("status", "unknown")
    _waf_detected = check_map_quick.get("waf",   {}).get("status") == "ok"

    # ── Resolve domain → IPs ──────────────────────────────────────────────────
    ips = []
    try:
        info = _sock.getaddrinfo(domain, None)
        ips = list(dict.fromkeys(
            i[4][0] for i in info if ":" not in i[4][0]
        ))[:3]
    except Exception:
        pass

    # ── Shodan lookup per IP ──────────────────────────────────────────────────
    shodan_results = []
    if SHODAN_API_KEY and ips:
        for ip in ips[:2]:
            try:
                r = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": SHODAN_API_KEY},
                    timeout=15,
                )
                if r.status_code == 200:
                    sh = r.json()
                    services = []
                    for item in (sh.get("data") or []):
                        services.append({
                            "port":      item.get("port"),
                            "transport": item.get("transport", "tcp"),
                            "product":   item.get("product", ""),
                            "version":   item.get("version", ""),
                            "banner":    (item.get("data") or "")[:200],
                            "vulns":     list((item.get("vulns") or {}).keys()),
                        })
                    shodan_results.append({
                        "ip":         ip,
                        "org":        sh.get("org", ""),
                        "isp":        sh.get("isp", ""),
                        "os":         sh.get("os", ""),
                        "country":    sh.get("country_name", ""),
                        "open_ports": sh.get("ports", []),
                        "services":   services,
                        "vulns":      {k: v for k, v in (sh.get("vulns") or {}).items()},
                        "hostnames":  sh.get("hostnames", []),
                        "tags":       sh.get("tags", []),
                        "last_update": sh.get("last_update", ""),
                    })
                elif r.status_code == 404:
                    shodan_results.append({"ip": ip, "note": "not in Shodan index"})
            except Exception as e:
                shodan_results.append({"ip": ip, "error": str(e)})

    # ── ParanoidLab breach data ───────────────────────────────────────────────
    leaks_data: dict = {}
    try:
        leaks_data = paranoidlab_leaks(domain, limit=10)
    except Exception:
        pass

    leak_total = leaks_data.get("total", 0)

    # ── Build attack graph (nodes + edges) — solutions-page taxonomy ─────────
    # node types: entry (red)=CVE services/breach, pivot (amber)=IPs/clean svc,
    #             critical (lime)=the domain target, safe (blue)=no-risk services
    risk_score = scan_data.get("risk_score") or 0

    # MITRE ATT&CK technique by port
    _mitre = {
        22: "T1021.004", 23: "T1021", 3389: "T1021.001",
        21: "T1021", 2049: "T1021",
        25: "T1566", 465: "T1566", 587: "T1566",
        80: "T1190", 443: "T1190", 8080: "T1190", 8443: "T1190",
        3306: "T1190", 5432: "T1190", 1433: "T1190", 27017: "T1190",
        6379: "T1190", 9200: "T1190", 11211: "T1190",
        6667: "T1102", 4444: "T1059",
    }

    graph_nodes = [{
        "id": "domain_root", "label": domain,
        "type": "critical",
        "detail": f"Target domain\nRisk score: {risk_score}/100\nAll breach paths converge here",
        "cvss": 0,
    }]
    graph_edges = []

    for sh in shodan_results:
        ip = sh.get("ip", "")
        if not ip or sh.get("error") or sh.get("note"):
            continue
        ip_id = f"ip_{ip}"
        org = sh.get("org") or sh.get("isp") or ""
        graph_nodes.append({
            "id": ip_id, "label": ip, "type": "pivot",
            "detail": f"IP: {ip}\n{org}\nT1590 Gather Network Info",
            "cvss": 0,
        })
        # pivot IP → critical domain
        graph_edges.append({"from": ip_id, "to": "domain_root", "label": "T1590"})

        for svc in (sh.get("services") or [])[:6]:
            port = svc.get("port")
            svc_id = f"svc_{ip}_{port}"
            product = (svc.get("product") or svc.get("transport") or "").strip()
            version = (svc.get("version") or "").strip()
            label = f":{port} {product}".strip()
            vulns = svc.get("vulns") or []
            mitre = _mitre.get(port, "T1190")

            if vulns:
                cve_summary = ", ".join(vulns[:3])
                detail = f"{product} {version}\n{cve_summary}\n{mitre} Exploit Public-Facing App"
                graph_nodes.append({
                    "id": svc_id, "label": label, "type": "entry",
                    "detail": detail, "cvss": 8.0,
                })
                # entry service → pivot IP → critical domain
                graph_edges.append({"from": svc_id, "to": ip_id, "label": mitre})
            elif port in _mitre:
                detail = f"{product} {version}\n{mitre} Lateral Movement pivot"
                graph_nodes.append({
                    "id": svc_id, "label": label, "type": "pivot",
                    "detail": detail, "cvss": 0,
                })
                graph_edges.append({"from": svc_id, "to": ip_id, "label": "T1046"})
            else:
                detail = f"{product} {version}\nNo known vulnerabilities"
                graph_nodes.append({
                    "id": svc_id, "label": label, "type": "safe",
                    "detail": detail, "cvss": 0,
                })
                graph_edges.append({"from": svc_id, "to": ip_id, "label": "T1046"})

    if leak_total > 0:
        graph_nodes.append({
            "id": "leaks", "label": f"{leak_total} Creds",
            "type": "entry",
            "detail": f"{leak_total} leaked credentials found\nT1078 Valid Accounts\nDirect domain access via cred stuffing",
            "cvss": 7.0,
        })
        graph_edges.append({"from": "leaks", "to": "domain_root", "label": "T1078"})

    # ── AI attack narrative ───────────────────────────────────────────────────
    narrative: dict = {"summary": "", "attack_chain": [], "fix_priority": []}
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if api_key:
        port_summary = []
        all_cves = []
        for sh in shodan_results:
            for svc in (sh.get("services") or [])[:5]:
                label = f":{svc['port']} {svc.get('product','')} {svc.get('version','')}".strip()
                port_summary.append(label)
            for cve_id, cve_info in list((sh.get("vulns") or {}).items())[:4]:
                cvss = (cve_info or {}).get("cvss", "?")
                all_cves.append(f"{cve_id} (CVSS {cvss})")

        critical_checks = [c.get("check","") for c in checks if isinstance(c, dict) and c.get("status") == "critical"]

        prompt = (
            f"Domain: {domain}\n"
            f"Risk Score: {risk_score}/100  |  Max CVSS: {max(((cve_info or {}).get('cvss') or 0) for sh in shodan_results for cve_info in (sh.get('vulns') or {}).values()) if any(sh.get('vulns') for sh in shodan_results) else 0}\n"
            f"Resolved IPs: {', '.join(ips) or 'none'}\n"
            f"Open ports/services: {', '.join(port_summary[:8]) or 'none detected by Shodan'}\n"
            f"CVEs on this host: {', '.join(all_cves[:5]) or 'none'}\n"
            f"Credential leaks: {leak_total} records found in breach databases\n"
            f"WAF detected: {_waf_detected}\n"
            f"SPF: {_spf_status}  DMARC: {_dmarc_status}\n"
            f"Critical security gaps: {', '.join(critical_checks[:6]) or 'none'}\n\n"
            f"Write a realistic penetration tester's assessment with exactly these sections:\n\n"
            f"ATTACK SUMMARY\n"
            f"2-3 sentences describing the overall attack opportunity for this domain.\n\n"
            f"ATTACK CHAIN\n"
            f"4 numbered steps showing a realistic attack progression for this specific domain "
            f"(reconnaissance → initial access → exploitation → impact). Each step one sentence.\n\n"
            f"FIX PRIORITY\n"
            f"5 numbered remediation actions in priority order. Each on its own line starting with the number.\n"
        )
        try:
            result = _call_claude_sync(
                api_key=api_key,
                model="claude-haiku-4-5-20251001",
                max_tokens=900,
                system=(
                    "You are a senior penetration tester. Be direct and technical. "
                    "Base your assessment only on the evidence provided. "
                    "Never invent CVEs or IP addresses. If data is missing, say so briefly."
                ),
                messages=[{"role": "user", "content": prompt}],
                metadata={"report_type": "attack_surface", "_user": user["sub"], "domain": domain},
            )
            full_text = result.get("content", [{}])[0].get("text", "")
            current = None
            for line in full_text.split("\n"):
                t = line.strip()
                if not t:
                    continue
                if "ATTACK SUMMARY" in t.upper():
                    current = "summary"; continue
                if "ATTACK CHAIN" in t.upper():
                    current = "chain"; continue
                if "FIX PRIORITY" in t.upper():
                    current = "fix"; continue
                if current == "summary":
                    narrative["summary"] += t + " "
                elif current == "chain" and t and t[0].isdigit():
                    narrative["attack_chain"].append(t)
                elif current == "fix" and t and t[0].isdigit():
                    narrative["fix_priority"].append(t)
            narrative["summary"] = narrative["summary"].strip()
        except Exception as e:
            narrative["summary"] = f"AI narrative unavailable: {e}"

    _max_cvss = max(((cve_info or {}).get("cvss") or 0) for sh in shodan_results for cve_info in (sh.get("vulns") or {}).values()) if any(sh.get("vulns") for sh in shodan_results) else 0
    _critical_checks = [c.get("check","") for c in checks if isinstance(c, dict) and c.get("status") == "critical"]

    return {
        "domain":      domain,
        "ips":         ips,
        "risk_score":  risk_score,
        "max_cvss":    _max_cvss,
        "shodan":      shodan_results,
        "leaks":       {"total": leak_total, "items": (leaks_data.get("items") or [])[:5]},
        "graph":       {"nodes": graph_nodes, "edges": graph_edges},
        "narrative":   narrative,
        "scan_findings": {
            "critical": [c for c in checks if isinstance(c, dict) and c.get("status") == "critical"],
            "warnings":  [c for c in checks if isinstance(c, dict) and c.get("status") == "warning"],
        },
        "meta": {
            "shodan_available": bool(SHODAN_API_KEY),
            "paranoidlab_available": bool(PARANOIDLAB_API_KEY),
        },
        "ai_context": {
            "model": "claude-haiku-4-5-20251001",
            "system": (
                "You are a senior penetration tester. Be direct and technical. "
                "Base your assessment only on the evidence provided. "
                "Never invent CVEs or IP addresses. If data is missing, say so briefly."
            ),
            "evidence": {
                "domain": domain,
                "risk_score": risk_score,
                "max_cvss": _max_cvss,
                "resolved_ips": ips,
                "open_ports_services": [
                    f":{svc['port']} {svc.get('product','')} {svc.get('version','')}".strip()
                    for sh in shodan_results for svc in (sh.get("services") or [])[:5]
                ][:8],
                "cves": [
                    f"{cve_id} (CVSS {(cve_info or {}).get('cvss','?')})"
                    for sh in shodan_results
                    for cve_id, cve_info in list((sh.get("vulns") or {}).items())[:4]
                ][:5],
                "credential_leaks": leak_total,
                "waf_detected": _waf_detected,
                "spf_status": _spf_status,
                "dmarc_status": _dmarc_status,
                "critical_security_gaps": _critical_checks[:6],
            },
            "prompt_template": (
                "Domain: {domain}\n"
                "Risk Score: {risk_score}/100  |  Max CVSS: {max_cvss}\n"
                "Resolved IPs: {resolved_ips}\n"
                "Open ports/services: {open_ports_services}\n"
                "CVEs on this host: {cves}\n"
                "Credential leaks: {credential_leaks} records found in breach databases\n"
                "WAF detected: {waf_detected}\n"
                "SPF: {spf_status}  DMARC: {dmarc_status}\n"
                "Critical security gaps: {critical_security_gaps}\n\n"
                "Write a realistic penetration tester's assessment with exactly these sections:\n\n"
                "ATTACK SUMMARY\n"
                "2-3 sentences describing the overall attack opportunity for this domain.\n\n"
                "ATTACK CHAIN\n"
                "4 numbered steps showing a realistic attack progression for this specific domain "
                "(reconnaissance → initial access → exploitation → impact). Each step one sentence.\n\n"
                "FIX PRIORITY\n"
                "5 numbered remediation actions in priority order. Each on its own line starting with the number."
            ),
        },
    }


# ── Public contact form ────────────────────────────────────────────────────────
# ── XDR / SIEM Integrations ──────────────────────────────────────────────────

class IntegrationConfigRequest(BaseModel):
    config: dict
    enabled: bool = True


def _mask_config(config: dict) -> dict:
    """Replace secret values with masked placeholders so they're never returned to the client."""
    secret_keys = {"hec_token", "shared_key", "api_key", "api_token", "client_secret", "password", "secret"}
    return {
        k: ("••••••••" if k in secret_keys and v else v)
        for k, v in config.items()
    }


@app.get("/integrations")
def list_integrations(authorization: str = Header(None)):
    """List all configured integrations for the current user (secrets masked)."""
    user = get_user_from_header(authorization)
    db   = get_db()
    rows = (
        db.table("integration_configs")
        .select("id,service,config,enabled,last_fired_at,error_count,last_error,created_at,updated_at")
        .eq("user_id", user["sub"])
        .execute()
    )
    result = []
    for row in (rows.data or []):
        meta = CONNECTOR_META.get(row["service"], {})
        result.append({
            **row,
            "config":      _mask_config(row.get("config") or {}),
            "name":        meta.get("name", row["service"]),
            "logo":        meta.get("logo", "🔌"),
        })
    return {"integrations": result, "available": list(CONNECTOR_META.keys())}


@app.post("/integrations/{service}")
def save_integration(service: str, body: IntegrationConfigRequest, authorization: str = Header(None)):
    """Create or update an integration config for the given service."""
    if service not in CONNECTORS:
        raise HTTPException(400, f"Unknown service '{service}'. Valid: {list(CONNECTORS.keys())}")
    user = get_user_from_header(authorization)
    db   = get_db()
    now  = datetime.now(timezone.utc).isoformat()

    existing = (
        db.table("integration_configs")
        .select("id")
        .eq("user_id", user["sub"])
        .eq("service", service)
        .execute()
    )
    if existing.data:
        db.table("integration_configs").update({
            "config":     body.config,
            "enabled":    body.enabled,
            "updated_at": now,
        }).eq("user_id", user["sub"]).eq("service", service).execute()
    else:
        db.table("integration_configs").insert({
            "user_id":    user["sub"],
            "service":    service,
            "config":     body.config,
            "enabled":    body.enabled,
            "created_at": now,
            "updated_at": now,
        }).execute()

    return {"ok": True, "service": service}


@app.delete("/integrations/{service}")
def delete_integration(service: str, authorization: str = Header(None)):
    """Remove an integration config."""
    user = get_user_from_header(authorization)
    db   = get_db()
    db.table("integration_configs").delete().eq("user_id", user["sub"]).eq("service", service).execute()
    return {"ok": True}


@app.post("/integrations/{service}/test")
def test_integration(service: str, body: IntegrationConfigRequest, authorization: str = Header(None)):
    """Test connectivity for an integration without saving the config."""
    if service not in CONNECTORS:
        raise HTTPException(400, f"Unknown service '{service}'")
    get_user_from_header(authorization)  # auth check only
    try:
        connector = CONNECTORS[service](body.config)
        result = connector.test()
        return result
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ── TAXII 2.1 / STIX feed ────────────────────────────────────────────────────

@app.get("/taxii/collections/")
def taxii_discovery(authorization: str = Header(None)):
    """TAXII 2.1 collection discovery endpoint."""
    get_user_from_header(authorization)
    return {
        "title":       "SwarmHawk Threat Intel",
        "description": "Domain security findings as STIX 2.1",
        "id":          "swarmhawk",
        "can_read":    True,
        "can_write":   False,
        "media_types": ["application/stix+json;version=2.1"],
    }


@app.get("/taxii/collections/swarmhawk/objects/")
def taxii_objects(
    authorization: str = Header(None),
    min_risk: int = Query(70, ge=0, le=100),
    limit: int = Query(100, ge=1, le=500),
):
    """TAXII 2.1 objects endpoint — returns STIX 2.1 bundle of critical domain findings."""
    user = get_user_from_header(authorization)
    db   = get_db()
    rows = (
        db.table("scan_results")
        .select("domain,risk_score,max_cvss,priority,country,cves,created_at,last_scanned_at")
        .eq("user_id", user["sub"])
        .gte("risk_score", min_risk)
        .order("risk_score", desc=True)
        .limit(limit)
        .execute()
    )
    bundle = STIXConnector.build_bundle(rows.data or [])
    return bundle


# ── SSE real-time alert stream ────────────────────────────────────────────────

@app.get("/stream/alerts")
async def stream_alerts(
    request: Request,
    authorization: str = Header(None),
    min_risk: int = Query(80, ge=0, le=100),
):
    """Server-Sent Events stream — push new high-risk domain alerts to the dashboard.

    Clients receive events as: data: {JSON}\\n\\n
    Heartbeat (data: {"type":"heartbeat"}) sent every 25 s to keep the connection alive.

    Example JS client:
        const es = new EventSource('/stream/alerts?min_risk=80', {headers: {Authorization: 'Bearer ...'}});
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    user = get_user_from_header(authorization)

    q: asyncio.Queue = asyncio.Queue()
    _sse_listeners.append(q)

    async def event_generator():
        try:
            # Send connected event
            yield f"data: {json.dumps({'type': 'connected', 'min_risk': min_risk})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=25.0)
                    # Filter by risk threshold and user scope (pipeline events are global)
                    if event.get("risk_score", 0) >= min_risk:
                        yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield "data: {\"type\":\"heartbeat\"}\n\n"
        finally:
            try:
                _sse_listeners.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )


# ─────────────────────────────────────────────────────────────────────────────

class ContactFormRequest(BaseModel):
    first: str
    last: str
    email: str
    company: str = ""
    topic: str
    message: str

@app.post("/contact")
def submit_contact_form(body: ContactFormRequest):
    """Public: receive contact form submission and forward to hello@swarmhawk.com via Resend."""
    if not RESEND_API_KEY:
        raise HTTPException(503, "Email service not configured")

    # Basic validation
    if not body.first.strip() or not body.last.strip() or not body.email.strip() or not body.message.strip():
        raise HTTPException(400, "Required fields missing")
    if len(body.message) > 2000:
        raise HTTPException(400, "Message too long")

    topic_labels = {
        "sales": "Sales & Pricing Enquiry",
        "technical": "Technical Support Request",
        "api": "API & Integration Question",
        "enterprise": "Enterprise / Partnership",
        "security": "Security Vulnerability Report",
        "gdpr": "Privacy / GDPR Request",
        "media": "Press & Media Enquiry",
        "other": "General Enquiry",
    }

    to_email = (
        "security@swarmhawk.com"   if body.topic == "security"   else
        "privacy@swarmhawk.com"    if body.topic == "gdpr"        else
        "enterprise@swarmhawk.com" if body.topic == "enterprise"  else
        "hello@swarmhawk.com"
    )
    subject = f"[SwarmHawk] {topic_labels.get(body.topic, 'Enquiry')} — {body.first} {body.last}"

    html_body = f"""
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0E0D12;color:#fff;padding:32px;border-radius:8px">
      <div style="color:#CBFF00;font-family:monospace;font-size:18px;font-weight:700;margin-bottom:24px">SWARM<span style="color:#C0392B">HAWK</span> — Contact Form</div>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px">
        <tr><td style="padding:8px 0;color:#6B7280;font-size:13px;width:120px">From</td><td style="padding:8px 0;color:#fff;font-size:14px">{body.first} {body.last}</td></tr>
        <tr><td style="padding:8px 0;color:#6B7280;font-size:13px">Email</td><td style="padding:8px 0"><a href="mailto:{body.email}" style="color:#CBFF00">{body.email}</a></td></tr>
        {"<tr><td style='padding:8px 0;color:#6B7280;font-size:13px'>Company</td><td style='padding:8px 0;color:#fff;font-size:14px'>" + body.company + "</td></tr>" if body.company else ""}
        <tr><td style="padding:8px 0;color:#6B7280;font-size:13px">Topic</td><td style="padding:8px 0;color:#CBFF00;font-size:14px">{topic_labels.get(body.topic, body.topic)}</td></tr>
      </table>
      <div style="background:#111318;border:1px solid rgba(203,255,0,.1);border-radius:8px;padding:20px;font-size:15px;color:#b0adc0;line-height:1.7;white-space:pre-wrap">{body.message}</div>
      <div style="margin-top:24px;font-size:12px;color:#3d3c4a">Sent via swarmhawk.com/contact.html</div>
    </div>
    """

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from":     f"SwarmHawk Contact <{FROM_EMAIL}>",
                "to":       [to_email],
                "reply_to": [body.email],
                "subject":  subject,
                "html":     html_body,
            },
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            raise HTTPException(502, f"Email delivery failed: {resp.text}")
    except requests.RequestException as e:
        raise HTTPException(502, f"Email service unreachable: {e}")

    return {"ok": True, "delivered_to": to_email}
