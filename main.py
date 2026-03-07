"""
SwarmHawk Backend API
=====================
FastAPI backend for the CEE Cyber Intelligence SaaS platform.

Endpoints:
  POST /auth/google          — verify Google JWT, create/get user
  GET  /domains              — list user's domains
  POST /domains              — add domain (free)
  GET  /domains/{id}/report  — get scan report (free = partial, paid = full)
  POST /checkout             — create Stripe checkout session ($10)
  POST /webhook              — Stripe webhook → mark domain as paid
  GET  /admin/stats          — admin overview

Run locally:
  pip install fastapi uvicorn supabase stripe python-jose httpx
  uvicorn main:app --reload --port 8000
"""

import os
import json
import hmac
import hashlib
import httpx
import stripe
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt, JWTError
from supabase import create_client, Client

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL        = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY", "")        # anon/service key
STRIPE_SECRET_KEY   = os.getenv("STRIPE_SECRET_KEY", "")   # sk_live_... or sk_test_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")  # whsec_...
STRIPE_PRICE_ID     = os.getenv("STRIPE_PRICE_ID", "")     # price_... from Stripe dashboard
GOOGLE_CLIENT_ID    = os.getenv("GOOGLE_CLIENT_ID", "396286675021-tqhadhbp3jqc1jrqo5krk3j5njdss0cg.apps.googleusercontent.com")
FRONTEND_URL        = os.getenv("FRONTEND_URL", "https://hastikdan.github.io/cee-scanner")

stripe.api_key = STRIPE_SECRET_KEY

# ── Supabase client ───────────────────────────────────────────────────────────

db: Client = None

def get_db() -> Client:
    global db
    if db is None:
        db = create_client(SUPABASE_URL, SUPABASE_KEY)
    return db

# ── App ───────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    # Start daily outreach scan scheduler on startup
    try:
        from outreach import start_scheduler
        _scheduler = start_scheduler()
    except Exception as e:
        print(f"Scheduler init failed: {e}")
    yield

app = FastAPI(title="SwarmHawk API", version="2.0.0", lifespan=lifespan)

# Mount outreach router
try:
    from outreach import router as outreach_router
    app.include_router(outreach_router)
    print("Outreach router mounted at /outreach")
except Exception as e:
    print(f"Outreach router failed to load: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ────────────────────────────────────────────────────────────────────

class GoogleAuthRequest(BaseModel):
    credential: str   # JWT from Google Sign-In

class AddDomainRequest(BaseModel):
    domain: str
    country: str

class CheckoutRequest(BaseModel):
    domain_id: str
    domain: str

# ── Auth helpers ──────────────────────────────────────────────────────────────

async def verify_google_token(credential: str) -> dict:
    """Verify Google JWT and return payload."""
    try:
        async with httpx.AsyncClient() as client:
            # Get Google public keys
            r = await client.get("https://www.googleapis.com/oauth2/v3/certs")
            keys = r.json()

        # Decode without verification first to get kid
        header = jwt.get_unverified_header(credential)
        key = next((k for k in keys["keys"] if k["kid"] == header["kid"]), None)
        if not key:
            raise HTTPException(status_code=401, detail="Invalid Google token key")

        payload = jwt.decode(
            credential,
            key,
            algorithms=["RS256"],
            audience=GOOGLE_CLIENT_ID,
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


def get_user_from_header(authorization: str) -> dict:
    """Look up session token in sessions table and return user info."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = authorization.split(" ")[1]
    db = get_db()
    result = db.table("sessions").select("user_id").eq("token", token).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    user_id = result.data[0]["user_id"]
    return {"sub": user_id}

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.post("/auth/google")
async def auth_google(body: GoogleAuthRequest):
    """
    Verify Google credential JWT.
    Creates user in DB if first time, otherwise returns existing user.
    Returns a session token for subsequent requests.
    """
    payload = await verify_google_token(body.credential)

    google_id = payload["sub"]
    email     = payload["email"]
    name      = payload.get("name", "")
    avatar    = payload.get("picture", "")

    db = get_db()

    # Upsert user
    existing = db.table("users").select("*").eq("google_id", google_id).execute()

    if existing.data:
        user = existing.data[0]
        # Update last login
        db.table("users").update({
            "last_login": datetime.now(timezone.utc).isoformat(),
            "name": name,
            "avatar": avatar,
        }).eq("id", user["id"]).execute()
    else:
        # Create new user
        result = db.table("users").insert({
            "google_id": google_id,
            "email":     email,
            "name":      name,
            "avatar":    avatar,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": datetime.now(timezone.utc).isoformat(),
        }).execute()
        user = result.data[0]

    # Create simple session token (in production use Supabase Auth)
    import hashlib, secrets
    session_token = hashlib.sha256(
        f"{user['id']}:{secrets.token_hex(16)}".encode()
    ).hexdigest()

    # Store session
    db.table("sessions").upsert({
        "user_id": user["id"],
        "token":   session_token,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

    return {
        "user": {
            "id":     user["id"],
            "email":  email,
            "name":   name,
            "avatar": avatar,
        },
        "session_token": session_token,
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

    checks = latest.get("checks", [])

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


@app.get("/admin/stats")
def admin_stats(authorization: str = Header(None)):
    """Admin overview — total users, domains, revenue."""
    # In production: check user is admin
    db = get_db()
    users    = db.table("users").select("id", count="exact").execute()
    domains  = db.table("domains").select("id", count="exact").execute()
    purchases = db.table("purchases").select("amount_usd").execute()
    revenue  = sum(p["amount_usd"] for p in purchases.data)
    return {
        "total_users":   users.count,
        "total_domains": domains.count,
        "total_revenue": f"${revenue:.2f}",
        "total_sales":   len(purchases.data),
    }


# ── Background scan ───────────────────────────────────────────────────────────

def run_scan_background(domain_id: str, domain: str):
    """Run scanner in background and save results to DB."""
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)
        db = get_db()
        db.table("scans").insert({
            "domain_id":  domain_id,
            "risk_score": result["risk_score"],
            "critical":   result["critical"],
            "warnings":   result["warnings"],
            "checks":     json.dumps(result["checks"]),
            "scanned_at": result["scanned_at"],
        }).execute()
    except Exception as e:
        print(f"Background scan failed for {domain}: {e}")


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
