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

app = FastAPI(title="SwarmHawk API", version="2.0.0")

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
    """Extract and verify user JWT from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = authorization.split(" ")[1]
    try:
        # Verify using Supabase JWT secret
        payload = jwt.decode(token, os.getenv("SUPABASE_JWT_SECRET", ""), algorithms=["HS256"])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid session token")

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
