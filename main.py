import os
import json
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
from jose import jwt, JWTError
from supabase import create_client, Client

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://hastikdan.github.io/cee-scanner")

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI(title="SwarmHawk API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

db_client = None
def get_db():
    global db_client
    if db_client is None and SUPABASE_URL and SUPABASE_KEY:
        db_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return db_client

class GoogleAuthRequest(BaseModel):
    credential: str

class AddDomainRequest(BaseModel):
    domain: str
    country: str

class CheckoutRequest(BaseModel):
    domain_id: str
    domain: str

def get_user(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    token = authorization.split(" ")[1]
    db = get_db()
    if not db:
        raise HTTPException(status_code=500, detail="Database not configured")
    result = db.table("sessions").select("*, users(*)").eq("token", token).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="Invalid session")
    return result.data[0]["users"]

@app.get("/")
def root():
    return {"message": "SwarmHawk API is running"}

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}

@app.post("/auth/google")
async def auth_google(body: GoogleAuthRequest):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get("https://www.googleapis.com/oauth2/v3/certs")
            keys = r.json()
        header = jwt.get_unverified_header(body.credential)
        key = next((k for k in keys["keys"] if k["kid"] == header["kid"]), None)
        if not key:
            raise HTTPException(status_code=401, detail="Invalid token")
        payload = jwt.decode(body.credential, key, algorithms=["RS256"], audience=GOOGLE_CLIENT_ID)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    google_id = payload["sub"]
    email = payload["email"]
    name = payload.get("name", "")
    avatar = payload.get("picture", "")
    db = get_db()

    existing = db.table("users").select("*").eq("google_id", google_id).execute()
    if existing.data:
        user = existing.data[0]
        db.table("users").update({"last_login": datetime.now(timezone.utc).isoformat(), "name": name, "avatar": avatar}).eq("id", user["id"]).execute()
    else:
        result = db.table("users").insert({"google_id": google_id, "email": email, "name": name, "avatar": avatar, "created_at": datetime.now(timezone.utc).isoformat(), "last_login": datetime.now(timezone.utc).isoformat()}).execute()
        user = result.data[0]

    session_token = hashlib.sha256(f"{user['id']}:{secrets.token_hex(16)}".encode()).hexdigest()
    db.table("sessions").insert({"user_id": user["id"], "token": session_token, "created_at": datetime.now(timezone.utc).isoformat()}).execute()

    return {"user": {"id": user["id"], "email": email, "name": name, "avatar": avatar}, "session_token": session_token}

@app.get("/domains")
def list_domains(authorization: str = Header(None)):
    user = get_user(authorization)
    db = get_db()
    domains = db.table("domains").select("*").eq("user_id", user["id"]).order("created_at", desc=True).execute()
    result = []
    for d in domains.data:
        scans = db.table("scans").select("*").eq("domain_id", d["id"]).order("scanned_at", desc=True).execute()
        purchases = db.table("purchases").select("*").eq("domain_id", d["id"]).execute()
        latest = scans.data[0] if scans.data else None
        is_paid = len(purchases.data) > 0
        result.append({
            "id": d["id"],
            "domain": d["domain"],
            "country": d["country"],
            "added": d["created_at"],
            "status": "active" if latest else "scanning",
            "paid": is_paid,
            "risk_score": latest["risk_score"] if latest else None,
            "scanned_at": latest["scanned_at"] if latest else None,
            "scan_history": [{"date": s["scanned_at"], "risk": s["risk_score"]} for s in reversed(scans.data)],
        })
    return {"domains": result}

@app.post("/domains")
def add_domain(body: AddDomainRequest, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    user = get_user(authorization)
    import re
    if not re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', body.domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    db = get_db()
    existing = db.table("domains").select("id").eq("user_id", user["id"]).eq("domain", body.domain.lower()).execute()
    if existing.data:
        raise HTTPException(status_code=409, detail="Domain already added")
    result = db.table("domains").insert({"user_id": user["id"], "domain": body.domain.lower(), "country": body.country, "created_at": datetime.now(timezone.utc).isoformat()}).execute()
    domain_record = result.data[0]
    background_tasks.add_task(run_scan, domain_record["id"], body.domain)
    return {"id": domain_record["id"], "domain": body.domain, "status": "scanning"}

@app.post("/checkout")
def create_checkout(body: CheckoutRequest, authorization: str = Header(None)):
    user = get_user(authorization)
    db = get_db()
    domain = db.table("domains").select("id,domain").eq("id", body.domain_id).eq("user_id", user["id"]).execute()
    if not domain.data:
        raise HTTPException(status_code=404, detail="Domain not found")
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price_data": {"currency": "usd", "unit_amount": 1000, "product_data": {"name": f"Full Security Report — {body.domain}"}}, "quantity": 1}],
            mode="payment",
            success_url=f"{FRONTEND_URL}?payment=success&domain_id={body.domain_id}",
            cancel_url=f"{FRONTEND_URL}?payment=cancelled",
            metadata={"user_id": str(user["id"]), "domain_id": str(body.domain_id), "domain": body.domain},
            customer_email=user.get("email", ""),
        )
        return {"checkout_url": session.url, "session_id": session.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    if event["type"] == "checkout.session.completed":
        meta = event["data"]["object"].get("metadata", {})
        if meta.get("user_id") and meta.get("domain_id"):
            db = get_db()
            db.table("purchases").insert({"user_id": meta["user_id"], "domain_id": meta["domain_id"], "stripe_session_id": event["data"]["object"]["id"], "amount_usd": 10.00, "paid_at": datetime.now(timezone.utc).isoformat()}).execute()
    return {"received": True}

@app.get("/admin/stats")
def admin_stats():
    db = get_db()
    users = db.table("users").select("id", count="exact").execute()
    domains = db.table("domains").select("id", count="exact").execute()
    purchases = db.table("purchases").select("amount_usd").execute()
    revenue = sum(float(p["amount_usd"]) for p in purchases.data)
    return {"total_users": users.count, "total_domains": domains.count, "total_revenue": f"${revenue:.2f}", "total_sales": len(purchases.data)}

def run_scan(domain_id: str, domain: str):
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)
        db = get_db()
        db.table("scans").insert({"domain_id": domain_id, "risk_score": result["risk_score"], "critical": result["critical"], "warnings": result["warnings"], "checks": json.dumps(result["checks"]), "scanned_at": result["scanned_at"]}).execute()
    except Exception as e:
        print(f"Scan failed for {domain}: {e}")
