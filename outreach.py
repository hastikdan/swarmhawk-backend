"""
outreach.py — SwarmHawk Automated Outreach Engine
==================================================

Daily flow:
  1. Cron hits POST /outreach/run-scan  (or APScheduler on Render)
  2. Passive scan runs against PROSPECT_DOMAINS list
  3. Domains with CVSS >= threshold land in `outreach_prospects` table with status='pending'
  4. Daniel opens /outreach UI → reviews each card, edits email body, approves/skips
  5. POST /outreach/{id}/approve  → marks as approved
  6. POST /outreach/send-approved → Resend sends all approved emails, status→'sent'

Tables needed (run schema_outreach.sql in Supabase):
  outreach_prospects
  outreach_log
"""

import os, re, time, json, hashlib, asyncio
from datetime import datetime, timezone
from typing import Optional

import httpx
import requests as req
from fastapi import APIRouter, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel

# ── Router ────────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/outreach", tags=["outreach"])

# ── Config ────────────────────────────────────────────────────────────────────
RESEND_API_KEY   = os.getenv("RESEND_API_KEY", "")
ANTHROPIC_KEY    = os.getenv("ANTHROPIC_API_KEY", "")
FROM_EMAIL       = os.getenv("OUTREACH_FROM", "security@swarmhawk.eu")
FROM_NAME        = "SwarmHawk Security"
CVSS_THRESHOLD   = float(os.getenv("OUTREACH_CVSS_MIN", "7.0"))   # HIGH+
DAILY_SEND_LIMIT = int(os.getenv("OUTREACH_DAILY_LIMIT", "20"))    # max emails/day

TIMEOUT = 10
UA = {"User-Agent": "Mozilla/5.0 (compatible; SwarmHawk-Scout/1.0)"}

# ── Domain list (7 CEE countries × ~50 SMEs) ─────────────────────────────────
PROSPECT_DOMAINS = {
    "CZ": [
        "bonami.cz","datart.cz","kasa.cz","tsbohemia.cz","electroworld.cz","okay.cz",
        "sportisimo.cz","intersport.cz","hervis.cz","fler.cz","kosik.cz","rohlik.cz",
        "alza.cz","czc.cz","fakturoid.cz","flexibee.cz","pohoda.cz","money.cz",
        "dr-max.cz","benu.cz","pilulka.cz","invia.cz","fischer.cz","cedok.cz",
        "denik.cz","blesk.cz","reflex.cz","zive.cz","lupa.cz","cnews.cz","root.cz",
        "edux.cz","scio.cz","linet.cz","zetor.cz","prozeny.cz","sbazar.cz","sauto.cz",
        "portaldph.cz","dauc.cz","wedos.cz","forpsi.cz","active24.cz","ignum.cz",
    ],
    "PL": [
        "ceneo.pl","olx.pl","empik.com","media-expert.pl","neonet.pl","morele.net",
        "x-kom.pl","komputronik.pl","eobuwie.pl","answear.com","pracuj.pl","nocowanie.pl",
        "abczdrowie.pl","medonet.pl","wyborcza.pl","tvn24.pl","rmf.pl",
        "eduweb.pl","wsb.pl","doz.pl","superpharm.pl","itaka.pl","neckermann.pl",
        "morizon.pl","otodom.pl","faktura.pl","ifirma.pl","wfirma.pl","nazwa.pl",
        "home.pl","cyberfolks.pl","zenbox.pl",
    ],
    "SK": [
        "heureka.sk","sme.sk","aktuality.sk","pravda.sk","dennikn.sk","jobs.sk",
        "profesia.sk","csob.sk","vub.sk","slsp.sk","tatrabanka.sk","drmax.sk","benu.sk",
        "websupport.sk","active24.sk","nay.sk","datart.sk","ticketportal.sk",
        "azet.sk","topky.sk","cas.sk","invia.sk","fischer.sk",
    ],
    "HU": [
        "extreme-digital.hu","mediamarkt.hu","euronics.hu","origo.hu","index.hu",
        "hvg.hu","444.hu","telex.hu","apro.hu","profession.hu","otp.hu","kh.hu",
        "mkb.hu","drmax.hu","szallas.hu","ingatlan.com","rtl.hu","tv2.hu",
        "upc.hu","telekom.hu","tesco.hu","aldi.hu","spar.hu",
    ],
    "RO": [
        "pcgarage.ro","altex.ro","flanco.ro","cel.ro","digi24.ro","antena3.ro",
        "protv.ro","job.ro","ejobs.ro","bestjobs.ro","bcr.ro","brd.ro","raiffeisen.ro",
        "imobiliare.ro","storia.ro","orange.ro","vodafone.ro","telekom.ro",
        "kaufland.ro","lidl.ro","auchan.ro","elefant.ro","libris.ro",
    ],
    "AT": [
        "willhaben.at","derstandard.at","diepresse.com","krone.at","kurier.at",
        "karriere.at","stepstone.at","raiffeisen.at","erste.at","bawag.com",
        "apotheke.at","booking.at","tiscover.at","mediamarkt.at","billa.at",
        "spar.at","hofer.at","penny.at","oebb.at","wienerlinien.at",
    ],
    "DE": [
        "otto.de","idealo.de","check24.de","spiegel.de","zeit.de","faz.net",
        "stepstone.de","commerzbank.de","dkb.de","dm.de","rossmann.de",
        "booking.de","immonet.de","immowelt.de","mediamarkt.de","cyberport.de",
        "aldi.de","lidl.de","rewe.de","bahn.de",
    ],
}

# ── Header / version detection ────────────────────────────────────────────────
HEADER_PATTERNS = [
    (r"nginx/(\d+\.\d+(?:\.\d+)?)",        "nginx"),
    (r"Apache/(\d+\.\d+(?:\.\d+)?)",        "Apache"),
    (r"Microsoft-IIS/(\d+\.\d+)",           "IIS"),
    (r"PHP/(\d+\.\d+(?:\.\d+)?)",           "PHP"),
    (r"WordPress/(\d+\.\d+(?:\.\d+)?)",     "WordPress"),
    (r"Drupal (\d+(?:\.\d+)*)",             "Drupal"),
]
VERSION_PROBES = [
    ("/wp-json/",     r'"version":"(\d+\.\d+\.\d+)"',   "WordPress"),
    ("/wp-login.php", r'ver=(\d+\.\d+\.\d+)',            "WordPress"),
    ("/",             r'content="WordPress (\d+\.\d+)',  "WordPress"),
]

def detect_software(domain: str) -> list[dict]:
    found = []
    try:
        r = req.get(f"https://{domain}", timeout=TIMEOUT, headers=UA,
                    allow_redirects=True, verify=False)
        raw = " ".join(f"{k}: {v}" for k,v in r.headers.items())
        for pat, product in HEADER_PATTERNS:
            m = re.search(pat, raw, re.IGNORECASE)
            if m and not any(s["product"]==product for s in found):
                found.append({"product": product, "version": m.group(1)})
        body = r.text[:3000]
        for path, pat, product in VERSION_PROBES:
            if path == "/":
                m = re.search(pat, body, re.IGNORECASE)
                if m and not any(s["product"]==product for s in found):
                    found.append({"product": product, "version": m.group(1)})
    except Exception:
        pass
    for path, pat, product in VERSION_PROBES:
        if path == "/": continue
        try:
            r2 = req.get(f"https://{domain}{path}", timeout=TIMEOUT, headers=UA, verify=False)
            if r2.status_code == 200:
                m = re.search(pat, r2.text[:2000], re.IGNORECASE)
                if m and not any(s["product"]==product for s in found):
                    found.append({"product": product, "version": m.group(1)})
        except Exception:
            pass
    return found


def query_nvd(product: str, version: str) -> list[dict]:
    NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    KW  = {"nginx":"nginx","Apache":"apache http server","PHP":"php",
           "WordPress":"wordpress","Drupal":"drupal","IIS":"microsoft iis"}
    kw  = KW.get(product, product.lower())
    time.sleep(0.5)
    try:
        r = req.get(NVD, params={
            "keywordSearch": f"{kw} {version}",
            "cvssV3SeverityMin": "HIGH",
            "resultsPerPage": 5,
        }, timeout=12)
        if r.status_code != 200:
            return []
        cves = []
        for item in r.json().get("vulnerabilities", []):
            cve     = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score   = None
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            if score:
                cves.append({"id": cve["id"], "cvss": score, "product": product, "version": version})
        return sorted(cves, key=lambda x: x["cvss"], reverse=True)
    except Exception:
        return []


def scan_domain_passive(domain: str, country: str) -> Optional[dict]:
    software = detect_software(domain)
    if not software:
        return None
    cves = []
    for sw in software:
        if sw["version"] and sw["version"] != "unknown":
            cves.extend(query_nvd(sw["product"], sw["version"]))
    if not cves:
        return None
    max_cvss = max(c["cvss"] for c in cves)
    if max_cvss < CVSS_THRESHOLD:
        return None
    priority = "CRITICAL" if max_cvss >= 9 else "HIGH" if max_cvss >= 7 else "MEDIUM"
    return {
        "domain":   domain,
        "country":  country,
        "software": software,
        "cves":     cves[:5],
        "max_cvss": max_cvss,
        "priority": priority,
    }


# ── Claude email generation ───────────────────────────────────────────────────

def generate_email_body(prospect: dict) -> str:
    """Call Claude to draft personalised outreach email."""
    if not ANTHROPIC_KEY:
        return _fallback_email(prospect)

    top_cve = prospect["cves"][0]
    sw_list  = ", ".join(f"{s['product']} {s['version']}" for s in prospect["software"])
    cve_list = ", ".join(f"{c['id']} CVSS {c['cvss']}" for c in prospect["cves"][:3])

    prompt = (
        f"Write a short professional cold outreach email (6-8 sentences) "
        f"from SwarmHawk, a European cybersecurity intelligence company, "
        f"to the webmaster or IT manager of {prospect['domain']}.\n\n"
        f"Findings from our passive scan:\n"
        f"- Exposed software: {sw_list}\n"
        f"- Live CVEs: {cve_list}\n\n"
        f"Requirements:\n"
        f"1. Subject line on first line as: Subject: <subject>\n"
        f"2. Open with {top_cve['id']} (CVSS {top_cve['cvss']}) as concrete proof\n"
        f"3. One sentence plain-language risk explanation\n"
        f"4. Reference NIS2 compliance briefly\n"
        f"5. Offer a free full security report at swarmhawk.eu\n"
        f"6. Professional, direct — not alarmist\n"
        f"7. Sign off: The SwarmHawk Team | swarmhawk.eu\n\n"
        f"Output ONLY the email. No preamble. No markdown."
    )
    try:
        r = req.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 500,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=20,
        )
        if r.status_code == 200:
            return r.json()["content"][0]["text"].strip()
    except Exception:
        pass
    return _fallback_email(prospect)


def _fallback_email(p: dict) -> str:
    top = p["cves"][0]
    sw  = p["software"][0]
    return (
        f"Subject: Security vulnerability detected on {p['domain']} — {top['id']} CVSS {top['cvss']}\n\n"
        f"Dear {p['domain']} team,\n\n"
        f"Our automated security scanner detected {top['id']} (CVSS {top['cvss']}) "
        f"on your server running {sw['product']} {sw['version']}. "
        f"This is a publicly known vulnerability that could expose your organisation "
        f"to data breaches and NIS2 compliance penalties.\n\n"
        f"We have prepared a free full security report for {p['domain']} including "
        f"exact findings and remediation steps. Visit swarmhawk.eu or reply to this "
        f"email to access it.\n\n"
        f"The SwarmHawk Team | swarmhawk.eu"
    )


# ── Supabase helpers ──────────────────────────────────────────────────────────

def get_db():
    from supabase import create_client
    return create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))


def upsert_prospect(p: dict, email_body: str):
    """Insert or update prospect — don't re-add if already sent this week."""
    db   = get_db()
    pid  = hashlib.sha256(p["domain"].encode()).hexdigest()[:16]
    now  = datetime.now(timezone.utc).isoformat()
    existing = db.table("outreach_prospects").select("id,status").eq("domain", p["domain"]).execute()

    if existing.data:
        row = existing.data[0]
        # Don't overwrite if approved/sent — just update CVE data
        if row["status"] in ("approved", "sent"):
            db.table("outreach_prospects").update({
                "cves":      json.dumps(p["cves"]),
                "max_cvss":  p["max_cvss"],
                "scanned_at": now,
            }).eq("id", row["id"]).execute()
            return
        # Re-draft email if still pending
        db.table("outreach_prospects").update({
            "software":    json.dumps(p["software"]),
            "cves":        json.dumps(p["cves"]),
            "max_cvss":    p["max_cvss"],
            "priority":    p["priority"],
            "email_body":  email_body,
            "status":      "pending",
            "scanned_at":  now,
        }).eq("id", row["id"]).execute()
    else:
        db.table("outreach_prospects").insert({
            "id":          pid,
            "domain":      p["domain"],
            "country":     p["country"],
            "software":    json.dumps(p["software"]),
            "cves":        json.dumps(p["cves"]),
            "max_cvss":    p["max_cvss"],
            "priority":    p["priority"],
            "email_body":  email_body,
            "status":      "pending",
            "scanned_at":  now,
        }).execute()


# ── API endpoints ─────────────────────────────────────────────────────────────

class EmailUpdate(BaseModel):
    email_body: str

class BulkApprove(BaseModel):
    ids: list[str]


def require_admin(authorization: str):
    """Simple admin check — same session token validation."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing auth")
    token = authorization.split(" ")[1]
    db     = get_db()
    result = db.table("sessions").select("user_id").eq("token", token).execute()
    if not result.data:
        raise HTTPException(401, "Invalid session")
    # Optional: check user is in admin list
    admin_email = os.getenv("ADMIN_EMAIL", "")
    if admin_email:
        user = db.table("users").select("email").eq("id", result.data[0]["user_id"]).execute()
        if not user.data or user.data[0]["email"] != admin_email:
            raise HTTPException(403, "Admin only")


@router.post("/run-scan")
async def run_scan(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Trigger daily prospect scan. Called by cron or manually."""
    require_admin(authorization)
    background_tasks.add_task(_run_scan_job)
    return {"status": "scan started", "domains": sum(len(v) for v in PROSPECT_DOMAINS.values())}


def _run_scan_job():
    """Background job: scan all prospect domains, upsert findings."""
    import urllib3
    urllib3.disable_warnings()

    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_domains = [(d, c) for c, ds in PROSPECT_DOMAINS.items() for d in ds]
    found = 0

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(scan_domain_passive, domain, country): (domain, country)
                   for domain, country in all_domains}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    email_body = generate_email_body(result)
                    upsert_prospect(result, email_body)
                    found += 1
            except Exception as e:
                domain, _ = futures[future]
                print(f"Scan error {domain}: {e}")

    print(f"[outreach] scan complete — {found} new prospects found")

    # Log the run
    try:
        db = get_db()
        db.table("outreach_log").insert({
            "event":     "daily_scan",
            "prospects": found,
            "ran_at":    datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception:
        pass


@router.get("/prospects")
async def list_prospects(
    status:      str = "pending",
    country:     str = "",
    min_cvss:    float = 0,
    authorization: str = Header(None),
):
    """List prospects for review dashboard. Filter by status/country/cvss."""
    require_admin(authorization)
    db = get_db()
    q  = db.table("outreach_prospects").select("*")
    if status != "all":
        q = q.eq("status", status)
    if country:
        q = q.eq("country", country)
    if min_cvss > 0:
        q = q.gte("max_cvss", min_cvss)
    result = q.order("max_cvss", desc=True).limit(200).execute()

    rows = []
    for r in (result.data or []):
        rows.append({
            **r,
            "software": json.loads(r["software"]) if isinstance(r["software"], str) else r["software"],
            "cves":     json.loads(r["cves"]) if isinstance(r["cves"], str) else r["cves"],
        })
    return {"prospects": rows, "total": len(rows)}


@router.patch("/prospects/{prospect_id}/email")
async def update_email(
    prospect_id: str,
    body: EmailUpdate,
    authorization: str = Header(None),
):
    """Save manually edited email body."""
    require_admin(authorization)
    db = get_db()
    db.table("outreach_prospects").update({
        "email_body":  body.email_body,
        "edited":      True,
    }).eq("id", prospect_id).execute()
    return {"status": "saved"}


@router.post("/prospects/{prospect_id}/approve")
async def approve_prospect(prospect_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    db.table("outreach_prospects").update({"status": "approved"}).eq("id", prospect_id).execute()
    return {"status": "approved"}


@router.post("/prospects/{prospect_id}/skip")
async def skip_prospect(prospect_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    db.table("outreach_prospects").update({"status": "skipped"}).eq("id", prospect_id).execute()
    return {"status": "skipped"}


@router.post("/prospects/{prospect_id}/unapprove")
async def unapprove_prospect(prospect_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    db.table("outreach_prospects").update({"status": "pending"}).eq("id", prospect_id).execute()
    return {"status": "pending"}


@router.post("/prospects/bulk-approve")
async def bulk_approve(body: BulkApprove, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    for pid in body.ids:
        db.table("outreach_prospects").update({"status": "approved"}).eq("id", pid).execute()
    return {"approved": len(body.ids)}


@router.post("/send-approved")
async def send_approved(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Send all approved emails via Resend. Respects daily limit."""
    require_admin(authorization)
    background_tasks.add_task(_send_approved_job)
    return {"status": "sending started"}


def _send_approved_job():
    if not RESEND_API_KEY:
        print("[outreach] RESEND_API_KEY not set — skipping send")
        return

    db       = get_db()
    approved = db.table("outreach_prospects").select("*").eq("status", "approved").limit(DAILY_SEND_LIMIT).execute()
    sent     = 0

    for row in (approved.data or []):
        domain     = row["domain"]
        email_body = row["email_body"] or ""

        # Parse subject from first line if present
        lines   = email_body.strip().splitlines()
        subject = f"Security vulnerability detected on {domain}"
        body    = email_body
        if lines and lines[0].lower().startswith("subject:"):
            subject = lines[0][8:].strip()
            body    = "\n".join(lines[2:]).strip()  # skip subject + blank line

        # Best-guess webmaster email
        to_email = f"webmaster@{domain}"

        try:
            r = req.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={
                    "from":    f"{FROM_NAME} <{FROM_EMAIL}>",
                    "to":      [to_email],
                    "subject": subject,
                    "text":    body,
                    "html":    _text_to_html(body, domain),
                },
                timeout=15,
            )
            if r.status_code in (200, 201):
                db.table("outreach_prospects").update({
                    "status":  "sent",
                    "sent_at": datetime.now(timezone.utc).isoformat(),
                    "sent_to": to_email,
                }).eq("id", row["id"]).execute()
                db.table("outreach_log").insert({
                    "event":  "email_sent",
                    "domain": domain,
                    "to":     to_email,
                    "ran_at": datetime.now(timezone.utc).isoformat(),
                }).execute()
                sent += 1
                print(f"[outreach] sent → {to_email}")
            else:
                print(f"[outreach] Resend error {r.status_code} for {domain}: {r.text[:200]}")
        except Exception as e:
            print(f"[outreach] send error for {domain}: {e}")

        time.sleep(0.3)  # Resend rate limit

    print(f"[outreach] sent {sent} emails")


def _text_to_html(text: str, domain: str) -> str:
    """Convert plain text email to simple branded HTML."""
    paragraphs = "".join(f"<p style='margin:0 0 14px 0'>{p.strip()}</p>"
                         for p in text.split("\n\n") if p.strip())
    return f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;font-size:14px;color:#222;max-width:600px;margin:0 auto;padding:24px">
  <div style="border-left:3px solid #CBFF00;padding-left:16px;margin-bottom:24px">
    <strong style="font-family:monospace;font-size:16px;color:#0E0D12;background:#CBFF00;padding:4px 10px">SWARMHAWK</strong>
  </div>
  {paragraphs}
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="font-size:11px;color:#999">
    This is an automated security notification. To unsubscribe reply with "unsubscribe".<br>
    SwarmHawk Security Intelligence · swarmhawk.eu
  </p>
</body></html>"""


# ── APScheduler daily cron ────────────────────────────────────────────────────

def start_scheduler():
    """Call this from main.py startup to enable automatic daily scans."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        scheduler = BackgroundScheduler(timezone="Europe/Prague")
        # Scan at 06:00 Prague time daily
        scheduler.add_job(_run_scan_job, "cron", hour=6, minute=0, id="daily_prospect_scan")
        scheduler.start()
        print("[outreach] daily scan scheduler started — runs at 06:00 Prague time")
        return scheduler
    except ImportError:
        print("[outreach] APScheduler not installed — add apscheduler to requirements.txt")
        return None
