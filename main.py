"""
SwarmHawk Backend API v3.0
"""
import os, sys, json, hashlib, secrets, httpx, stripe
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from supabase import create_client, Client

SUPABASE_URL          = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY          = os.getenv("SUPABASE_KEY", "")
STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
GOOGLE_CLIENT_ID      = os.getenv("GOOGLE_CLIENT_ID", "396286675021-tqhadhbp3jqc1jrqo5krk3j5njdss0cg.apps.googleusercontent.com")
FRONTEND_URL          = os.getenv("FRONTEND_URL", "https://hastikdan.github.io/cee-scanner")
RESEND_API_KEY        = os.getenv("RESEND_API_KEY", "")
stripe.api_key        = STRIPE_SECRET_KEY

app = FastAPI(title="SwarmHawk API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

_db = None
def get_db():
    global _db
    if _db is None: _db = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _db

class GoogleAuthRequest(BaseModel): credential: str
class AddDomainRequest(BaseModel): domain: str; country: str = "EU"
class CheckoutRequest(BaseModel): domain_id: str; domain: str

def get_user(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing authorization")
    token = authorization.split(" ")[1]
    r = get_db().table("sessions").select("*, users(*)").eq("token", token).execute()
    if not r.data: raise HTTPException(401, "Invalid session")
    return r.data[0]["users"]

@app.get("/")
def root(): return {"message": "SwarmHawk API", "version": "3.0.0"}

@app.get("/health")
def health(): return {"status": "ok", "version": "3.0.0"}

@app.post("/auth/google")
async def auth_google(body: GoogleAuthRequest):
    async with httpx.AsyncClient() as c:
        keys = (await c.get("https://www.googleapis.com/oauth2/v3/certs")).json()
    header = jwt.get_unverified_header(body.credential)
    key = next((k for k in keys["keys"] if k["kid"] == header["kid"]), None)
    if not key: raise HTTPException(401, "Invalid token key")
    try:
        payload = jwt.decode(body.credential, key, algorithms=["RS256"], audience=GOOGLE_CLIENT_ID)
    except JWTError as e: raise HTTPException(401, str(e))
    google_id, email = payload["sub"], payload["email"]
    name, avatar = payload.get("name",""), payload.get("picture","")
    db = get_db()
    ex = db.table("users").select("*").eq("google_id", google_id).execute()
    if ex.data:
        user = ex.data[0]
        db.table("users").update({"last_login": datetime.now(timezone.utc).isoformat(),
                                   "name": name, "avatar": avatar}).eq("id", user["id"]).execute()
    else:
        user = db.table("users").insert({"google_id": google_id, "email": email, "name": name,
            "avatar": avatar, "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": datetime.now(timezone.utc).isoformat()}).execute().data[0]
    token = hashlib.sha256(f"{user['id']}:{secrets.token_hex(16)}".encode()).hexdigest()
    db.table("sessions").insert({"user_id": user["id"], "token": token,
                                  "created_at": datetime.now(timezone.utc).isoformat()}).execute()
    return {"user": {"id": user["id"], "email": email, "name": name, "avatar": avatar},
            "session_token": token}

@app.get("/domains")
def list_domains(authorization: str = Header(None)):
    user = get_user(authorization); db = get_db()
    result = []
    for d in db.table("domains").select("*").eq("user_id", user["id"]).order("created_at", desc=True).execute().data:
        scans = db.table("scans").select("*").eq("domain_id", d["id"]).order("scanned_at", desc=True).execute().data
        is_paid = len(db.table("purchases").select("id").eq("domain_id", d["id"]).execute().data) > 0
        latest = scans[0] if scans else None
        result.append({"id": d["id"], "domain": d["domain"], "country": d["country"],
            "added": d["created_at"], "status": "active" if latest else "scanning",
            "paid": is_paid, "risk_score": latest["risk_score"] if latest else None,
            "critical": latest["critical"] if latest else 0,
            "warnings": latest["warnings"] if latest else 0,
            "scanned_at": latest["scanned_at"] if latest else None,
            "scan_history": [{"date": s["scanned_at"], "risk": s["risk_score"]} for s in reversed(scans)]})
    return {"domains": result}

@app.post("/domains")
def add_domain(body: AddDomainRequest, bt: BackgroundTasks, authorization: str = Header(None)):
    user = get_user(authorization)
    import re
    domain = body.domain.lower().strip()
    if not re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
        raise HTTPException(400, "Invalid domain")
    db = get_db()
    if db.table("domains").select("id").eq("user_id", user["id"]).eq("domain", domain).execute().data:
        raise HTTPException(409, "Domain already added")
    rec = db.table("domains").insert({"user_id": user["id"], "domain": domain,
        "country": body.country, "created_at": datetime.now(timezone.utc).isoformat()}).execute().data[0]
    bt.add_task(run_scan, rec["id"], domain, body.country)
    return {"id": rec["id"], "domain": domain, "status": "scanning"}

@app.get("/domains/{domain_id}/report")
def get_report(domain_id: str, authorization: str = Header(None)):
    user = get_user(authorization); db = get_db()
    d = db.table("domains").select("*").eq("id", domain_id).eq("user_id", user["id"]).execute()
    if not d.data: raise HTTPException(404, "Domain not found")
    d = d.data[0]
    scans = db.table("scans").select("*").eq("domain_id", domain_id).order("scanned_at", desc=True).execute().data
    is_paid = len(db.table("purchases").select("id").eq("domain_id", domain_id).execute().data) > 0
    if not scans: return {"status": "scanning", "message": "Scan in progress — check back in 60 seconds"}
    latest = scans[0]
    checks = latest.get("checks", [])
    if isinstance(checks, str): checks = json.loads(checks)
    FREE = {"ssl","headers","dns","https_redirect","breach","urlhaus","safebrowsing","virustotal","spamhaus"}
    visible = checks if is_paid else [c for c in checks if c.get("check") in FREE]
    return {"domain": d["domain"], "country": d["country"], "risk_score": latest["risk_score"],
            "critical": latest["critical"], "warnings": latest["warnings"],
            "scanned_at": latest["scanned_at"], "paid": is_paid,
            "checks": visible, "locked_count": len(checks) - len(visible) if not is_paid else 0,
            "scan_history": [{"date": s["scanned_at"], "risk": s["risk_score"]} for s in reversed(scans)]}

@app.post("/checkout")
def create_checkout(body: CheckoutRequest, authorization: str = Header(None)):
    user = get_user(authorization); db = get_db()
    if not db.table("domains").select("id").eq("id", body.domain_id).eq("user_id", user["id"]).execute().data:
        raise HTTPException(404, "Domain not found")
    try:
        s = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price_data": {"currency": "eur", "unit_amount": 5000,
                "product_data": {"name": f"SwarmHawk Annual — {body.domain}",
                "description": "17 checks · Monthly AI reports · Remediation · 1 year"}}, "quantity": 1}],
            mode="payment",
            success_url=f"{FRONTEND_URL}?payment=success&domain_id={body.domain_id}",
            cancel_url=f"{FRONTEND_URL}?payment=cancelled",
            metadata={"user_id": str(user["id"]), "domain_id": str(body.domain_id),
                      "domain": body.domain, "email": user.get("email",""), "country": user.get("country","EU")},
            customer_email=user.get("email",""),
        )
        return {"checkout_url": s.url, "session_id": s.id}
    except Exception as e: raise HTTPException(400, str(e))

@app.post("/webhook")
async def stripe_webhook(request: Request, bt: BackgroundTasks):
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, request.headers.get("stripe-signature",""), STRIPE_WEBHOOK_SECRET)
    except Exception: raise HTTPException(400, "Invalid signature")
    if event["type"] == "checkout.session.completed":
        meta = event["data"]["object"].get("metadata", {})
        uid, did = meta.get("user_id"), meta.get("domain_id")
        if uid and did:
            get_db().table("purchases").insert({"user_id": uid, "domain_id": did,
                "stripe_session_id": event["data"]["object"]["id"],
                "amount_usd": 50.00, "paid_at": datetime.now(timezone.utc).isoformat()}).execute()
            if meta.get("domain") and meta.get("email"):
                bt.add_task(scan_and_email, did, meta["domain"], meta["email"], meta.get("country","EU"))
    return {"received": True}

@app.get("/admin/stats")
def admin_stats():
    db = get_db()
    p = db.table("purchases").select("amount_usd").execute().data
    return {"total_users": db.table("users").select("id", count="exact").execute().count,
            "total_domains": db.table("domains").select("id", count="exact").execute().count,
            "total_revenue": f"€{sum(float(x['amount_usd']) for x in p):.2f}",
            "total_sales": len(p)}

def run_scan(domain_id, domain, country="EU"):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from cee_scanner.checks import run_checks
        r = run_checks(domain); r["country"] = country
        get_db().table("scans").insert({"domain_id": domain_id, "risk_score": r["risk_score"],
            "critical": r["critical"], "warnings": r["warnings"],
            "checks": json.dumps(r.get("checks",[])), "scanned_at": r["scanned_at"]}).execute()
        print(f"Scan done: {domain} risk={r['risk_score']}")
    except Exception as e: print(f"Scan failed {domain}: {e}")

def scan_and_email(domain_id, domain, email, country="EU"):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from cee_scanner.checks import run_checks
        r = run_checks(domain); r["country"] = country
        get_db().table("scans").insert({"domain_id": domain_id, "risk_score": r["risk_score"],
            "critical": r["critical"], "warnings": r["warnings"],
            "checks": json.dumps(r.get("checks",[])), "scanned_at": r["scanned_at"]}).execute()
        if RESEND_API_KEY:
            from report_email import send_report
            send_report(email, r)
            print(f"Report sent to {email} for {domain}")
    except Exception as e: print(f"scan_and_email failed {domain}: {e}")
