"""
outreach.py — SwarmHawk Automated Prospect Intelligence Engine
==============================================================

Fully automated daily pipeline:
  1. 06:00 Prague → APScheduler fires _run_scan_job()
  2. fetch_country_domains() pulls top 500 domains per CEE country:
       a. Cloudflare Radar API (if CLOUDFLARE_API_TOKEN set) — country-aware rankings
       b. Tranco top-1M filtered by TLD (cached 24 h)
       c. Hardcoded extended fallback list
  3. Passive scan (software fingerprint + NVD CVE lookup) with 8 workers
  4. Contact discovery: security.txt → security@ → webmaster@
  5. Domains with CVSS >= threshold land in `outreach_prospects` table
  6. Claude AI drafts personalised cold email per prospect
  7. Admin reviews in /outreach tab, approves, clicks Send All

Tables needed (run schema_outreach.sql in Supabase):
  outreach_prospects
  outreach_log
"""

import os, re, time, json, hashlib, io, csv, zipfile
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
import requests as req
from fastapi import APIRouter, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel

# ── Router ────────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/outreach", tags=["outreach"])

# ── Config ────────────────────────────────────────────────────────────────────
RESEND_API_KEY      = os.getenv("RESEND_API_KEY", "")
ANTHROPIC_KEY       = os.getenv("ANTHROPIC_API_KEY", "")
FROM_EMAIL          = os.getenv("OUTREACH_FROM", "security@swarmhawk.eu")
FROM_NAME           = "SwarmHawk Security"
CVSS_THRESHOLD      = float(os.getenv("OUTREACH_CVSS_MIN", "7.0"))
DAILY_SEND_LIMIT    = int(os.getenv("OUTREACH_DAILY_LIMIT", "20"))
CLOUDFLARE_TOKEN    = os.getenv("CLOUDFLARE_API_TOKEN", "")
SCAN_LIMIT          = int(os.getenv("OUTREACH_SCAN_LIMIT", "500"))  # domains per country

TIMEOUT = 10
UA = {"User-Agent": "Mozilla/5.0 (compatible; SwarmHawk-Scout/1.0)"}

# ── Country → TLD mapping (global — 60+ countries) ───────────────────────────
COUNTRY_TLDS = {
    # Central & Eastern Europe
    "CZ": ".cz", "PL": ".pl", "SK": ".sk", "HU": ".hu", "RO": ".ro",
    "BG": ".bg", "HR": ".hr", "SI": ".si", "RS": ".rs", "UA": ".ua",
    "LT": ".lt", "LV": ".lv", "EE": ".ee", "BY": ".by", "MD": ".md",
    "AL": ".al", "MK": ".mk", "BA": ".ba", "ME": ".me", "XK": ".xk",
    # DACH
    "DE": ".de", "AT": ".at", "CH": ".ch",
    # Western Europe
    "GB": ".co.uk", "FR": ".fr", "ES": ".es", "IT": ".it", "NL": ".nl",
    "BE": ".be", "PT": ".pt", "IE": ".ie", "DK": ".dk", "SE": ".se",
    "NO": ".no", "FI": ".fi", "IS": ".is", "LU": ".lu", "MT": ".mt",
    # North America
    "CA": ".ca", "MX": ".mx",
    # Latin America
    "BR": ".com.br", "AR": ".com.ar", "CL": ".cl", "CO": ".co",
    "PE": ".pe", "VE": ".ve", "UY": ".com.uy",
    # Asia Pacific
    "AU": ".com.au", "NZ": ".co.nz", "JP": ".co.jp", "KR": ".co.kr",
    "SG": ".sg", "HK": ".hk", "TW": ".tw", "IN": ".co.in",
    "ID": ".co.id", "MY": ".com.my", "TH": ".co.th", "PH": ".com.ph",
    "VN": ".vn",
    # Middle East & Africa
    "IL": ".co.il", "AE": ".ae", "SA": ".com.sa", "ZA": ".co.za",
    "NG": ".com.ng", "EG": ".com.eg", "TR": ".com.tr",
    # Russia & CIS
    "RU": ".ru", "KZ": ".kz", "GE": ".ge", "AM": ".am", "AZ": ".az",
}

# ── Hardcoded fallback (extended) ─────────────────────────────────────────────
PROSPECT_DOMAINS = {
    "CZ": [
        "bonami.cz","datart.cz","kasa.cz","tsbohemia.cz","electroworld.cz","okay.cz",
        "sportisimo.cz","intersport.cz","hervis.cz","fler.cz","kosik.cz","rohlik.cz",
        "alza.cz","czc.cz","fakturoid.cz","flexibee.cz","pohoda.cz","money.cz",
        "dr-max.cz","benu.cz","pilulka.cz","invia.cz","fischer.cz","cedok.cz",
        "denik.cz","blesk.cz","reflex.cz","zive.cz","lupa.cz","cnews.cz","root.cz",
        "edux.cz","scio.cz","linet.cz","zetor.cz","prozeny.cz","sbazar.cz","sauto.cz",
        "portaldph.cz","dauc.cz","wedos.cz","forpsi.cz","active24.cz","ignum.cz",
        "stream.cz","nova.cz","ct.cz","idnes.cz","novinky.cz","seznam.cz","centrum.cz",
        "mall.cz","alzatech.cz","heureka.cz","zbozi.cz","slevomat.cz","favi.cz",
        "mall.cz","lidl.cz","kaufland.cz","tesco.cz","billa.cz","albert.cz",
    ],
    "PL": [
        "ceneo.pl","olx.pl","empik.com","media-expert.pl","neonet.pl","morele.net",
        "x-kom.pl","komputronik.pl","eobuwie.pl","answear.com","pracuj.pl","nocowanie.pl",
        "abczdrowie.pl","medonet.pl","wyborcza.pl","tvn24.pl","rmf.pl",
        "eduweb.pl","wsb.pl","doz.pl","superpharm.pl","itaka.pl","neckermann.pl",
        "morizon.pl","otodom.pl","faktura.pl","ifirma.pl","wfirma.pl","nazwa.pl",
        "home.pl","cyberfolks.pl","zenbox.pl","onet.pl","wp.pl","interia.pl",
        "allegro.pl","kaufland.pl","lidl.pl","biedronka.pl","carrefour.pl",
        "inpost.pl","dpd.pl","gls-poland.com","poczta-polska.pl","tpay.com",
        "przelewy24.pl","payu.pl","dotpay.pl","fiberpay.pl","autopay.pl",
    ],
    "SK": [
        "heureka.sk","sme.sk","aktuality.sk","pravda.sk","dennikn.sk","jobs.sk",
        "profesia.sk","csob.sk","vub.sk","slsp.sk","tatrabanka.sk","drmax.sk","benu.sk",
        "websupport.sk","active24.sk","nay.sk","datart.sk","ticketportal.sk",
        "azet.sk","topky.sk","cas.sk","invia.sk","fischer.sk","mall.sk",
        "tesco.sk","billa.sk","lidl.sk","kaufland.sk","ikea.sk","alza.sk",
    ],
    "HU": [
        "extreme-digital.hu","mediamarkt.hu","euronics.hu","origo.hu","index.hu",
        "hvg.hu","444.hu","telex.hu","apro.hu","profession.hu","otp.hu","kh.hu",
        "mkb.hu","drmax.hu","szallas.hu","ingatlan.com","rtl.hu","tv2.hu",
        "upc.hu","telekom.hu","tesco.hu","aldi.hu","spar.hu","mall.hu",
        "emag.hu","argep.hu","prohardver.hu","pcworld.hu","nlc.hu","borsonline.hu",
    ],
    "RO": [
        "pcgarage.ro","altex.ro","flanco.ro","cel.ro","digi24.ro","antena3.ro",
        "protv.ro","job.ro","ejobs.ro","bestjobs.ro","bcr.ro","brd.ro","raiffeisen.ro",
        "imobiliare.ro","storia.ro","orange.ro","vodafone.ro","telekom.ro",
        "kaufland.ro","lidl.ro","auchan.ro","elefant.ro","libris.ro","emag.ro",
        "okfin.ro","nefis.ro","stirileprotv.ro","jurnalul.ro","adevarul.ro",
    ],
    "AT": [
        "willhaben.at","derstandard.at","diepresse.com","krone.at","kurier.at",
        "karriere.at","stepstone.at","raiffeisen.at","erste.at","bawag.com",
        "apotheke.at","tiscover.at","mediamarkt.at","billa.at","spar.at",
        "hofer.at","penny.at","oebb.at","wienerlinien.at","orf.at",
        "amazon.at","otto.at","universal.at","herold.at","firmen.at",
    ],
    "DE": [
        "otto.de","idealo.de","check24.de","spiegel.de","zeit.de","faz.net",
        "stepstone.de","commerzbank.de","dkb.de","dm.de","rossmann.de",
        "immonet.de","immowelt.de","mediamarkt.de","cyberport.de",
        "aldi.de","lidl.de","rewe.de","bahn.de","ebay.de",
        "saturn.de","notebooksbilliger.de","computeruniverse.net","mindfactory.de",
        "mymemory.de","alternate.de","expert.de","euronics.de","conrad.de",
    ],
    "BG": [
        "technopolis.bg","technomarket.bg","fantastico.bg","emag.bg","olx.bg",
        "mobile.bg","imot.bg","autotrader.bg","24chasa.bg","dnevnik.bg",
        "investor.bg","manager.bg","novinite.bg","actualno.com","money.bg",
        "ubb.bg","fibank.bg","dsk.bg","unicreditbulbank.bg","postbank.bg",
    ],
    "HR": [
        "njuskalo.hr","oglasnik.hr","index.hr","tportal.hr","jutarnji.hr",
        "24sata.hr","hrt.hr","pbz.hr","zaba.hr","erste.hr","otpbanka.hr",
        "konzum.hr","plodine.hr","studenac.hr","kaufland.hr","lidl.hr",
        "sancta-domenica.hr","links.hr","optika-matica.hr","pevec.hr",
    ],
    "SI": [
        "mimovrste.si","big-bang.si","mall.si","siol.net","24ur.com",
        "rtvslo.si","finance.si","delo.si","dnevnik.si","vecer.com",
        "nlb.si","skb.si","sparkasse.si","abanka.si","nova-kbm.si",
        "mercator.si","spar.si","lidl.si","engrotuš.si","jub.si",
    ],
    "RS": [
        "halo.rs","oglasi.rs","kupujemprodajem.com","blic.rs","b92.net",
        "rts.rs","n1info.com","telegraf.rs","espreso.rs","naslovi.net",
        "banca.rs","nlb.rs","kombank.rs","unicreditbank.rs","mts.rs",
        "telenor.rs","a1.rs","vip.rs","gigatron.rs","tehnomanija.rs",
    ],
    "UA": [
        "rozetka.ua","prom.ua","olx.ua","allo.ua","foxtrot.ua",
        "epicentrk.ua","comfy.ua","moyo.ua","nova.poshta.ua","ukrposhta.ua",
        "privatbank.ua","oschadbank.ua","monobank.ua","alphabank.ua","a-bank.ua",
        "delo.ua","ukrinform.ua","pravda.com.ua","unian.ua","rbc.ua",
    ],
    "LT": [
        "pigu.lt","varle.lt","skelbiu.lt","aruodas.lt","autoplius.lt",
        "delfi.lt","lrytas.lt","15min.lt","alfa.lt","tv3.lt",
        "seb.lt","swedbank.lt","luminor.lt","siauliu-bankas.lt","medicinos-bankas.lt",
        "maxima.lt","rimi.lt","iki.lt","norfa.lt","lidl.lt",
    ],
    "LV": [
        "ss.lv","city24.lv","reklama.lv","tvnet.lv","delfi.lv",
        "la.lv","diena.lv","lsm.lv","nra.lv","ir.lv",
        "seb.lv","swedbank.lv","luminor.lv","citadele.lv","norvik.lv",
        "rimi.lv","maxima.lv","top.lv","drogas.lv","euroaptieka.lv",
    ],
    "EE": [
        "osta.ee","hinnavaatlus.ee","kv.ee","auto24.ee","city24.ee",
        "delfi.ee","err.ee","postimees.ee","epl.delfi.ee","aripaev.ee",
        "seb.ee","swedbank.ee","luminor.ee","lhv.ee","coop.ee",
        "prisma.ee","maxima.ee","rimi.ee","selver.ee","ülmar.ee",
    ],
}

# ── Tranco list cache ─────────────────────────────────────────────────────────
_tranco_cache: dict = {"domains": [], "fetched_at": None}


def _get_tranco_domains(tld: str, limit: int) -> list[str]:
    """Download Tranco top-1M (cached 24 h) and filter by country TLD."""
    global _tranco_cache
    now = datetime.now(timezone.utc)
    age = (now - _tranco_cache["fetched_at"]).total_seconds() if _tranco_cache["fetched_at"] else 99999
    if age > 86400 or not _tranco_cache["domains"]:
        print("[tranco] Downloading top-1M list…")
        try:
            r = req.get("https://tranco-list.eu/top-1m.csv.zip", timeout=60)
            r.raise_for_status()
            z = zipfile.ZipFile(io.BytesIO(r.content))
            with z.open(z.namelist()[0]) as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                _tranco_cache["domains"] = [row[1] for row in reader if len(row) >= 2]
            _tranco_cache["fetched_at"] = now
            print(f"[tranco] Loaded {len(_tranco_cache['domains'])} domains")
        except Exception as e:
            print(f"[tranco] Download failed: {e}")
            return []
    return [d for d in _tranco_cache["domains"] if d.endswith(tld)][:limit]


def _get_cloudflare_domains(country_code: str, limit: int) -> list[str]:
    """Cloudflare Radar country-specific top domains (requires CLOUDFLARE_API_TOKEN)."""
    if not CLOUDFLARE_TOKEN:
        return []
    try:
        r = req.get(
            "https://api.cloudflare.com/client/v4/radar/ranking/top",
            headers={"Authorization": f"Bearer {CLOUDFLARE_TOKEN}"},
            params={"location": country_code, "limit": limit, "format": "json"},
            timeout=15,
        )
        if r.status_code == 200:
            domains = [row["domain"] for row in r.json().get("result", {}).get("top", [])]
            if domains:
                print(f"[cloudflare-radar] {country_code}: {len(domains)} domains")
                return domains
        else:
            print(f"[cloudflare-radar] {country_code}: HTTP {r.status_code}")
    except Exception as e:
        print(f"[cloudflare-radar] {country_code} failed: {e}")
    return []


def fetch_country_domains(country_code: str, limit: int = 500) -> list[str]:
    """Return up to `limit` top domains for a country.
    Priority: Cloudflare Radar → Tranco TLD filter → hardcoded fallback."""
    # 1. Cloudflare Radar (country-aware, best quality)
    domains = _get_cloudflare_domains(country_code, limit)
    if len(domains) >= 50:
        return domains[:limit]

    # 2. Tranco list filtered by country TLD
    tld = COUNTRY_TLDS.get(country_code, "")
    if tld:
        domains = _get_tranco_domains(tld, limit)
        if domains:
            print(f"[tranco] {country_code}{tld}: {len(domains)} domains")
            return domains

    # 3. Hardcoded fallback
    fallback = PROSPECT_DOMAINS.get(country_code, [])
    print(f"[fallback] {country_code}: {len(fallback)} domains (hardcoded)")
    return fallback[:limit]


# ── Contact email discovery ────────────────────────────────────────────────────

def discover_contact_email(domain: str) -> str:
    """Try security.txt → fallback to security@ / webmaster@."""
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = req.get(f"https://{domain}{path}", timeout=5, headers=UA, verify=False)
            if r.status_code == 200 and "Contact:" in r.text:
                m = re.search(r"Contact:\s*(?:mailto:)?([^\s]+@[^\s]+)", r.text, re.IGNORECASE)
                if m:
                    email = m.group(1).strip().rstrip(".")
                    if "@" in email and "." in email.split("@")[1]:
                        return email
        except Exception:
            pass
    # Fall back to security@ (higher open rate than webmaster@)
    return f"security@{domain}"


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
        raw = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        for pat, product in HEADER_PATTERNS:
            m = re.search(pat, raw, re.IGNORECASE)
            if m and not any(s["product"] == product for s in found):
                found.append({"product": product, "version": m.group(1)})
        body = r.text[:3000]
        for path, pat, product in VERSION_PROBES:
            if path == "/":
                m = re.search(pat, body, re.IGNORECASE)
                if m and not any(s["product"] == product for s in found):
                    found.append({"product": product, "version": m.group(1)})
    except Exception:
        pass
    for path, pat, product in VERSION_PROBES:
        if path == "/":
            continue
        try:
            r2 = req.get(f"https://{domain}{path}", timeout=TIMEOUT, headers=UA, verify=False)
            if r2.status_code == 200:
                m = re.search(pat, r2.text[:2000], re.IGNORECASE)
                if m and not any(s["product"] == product for s in found):
                    found.append({"product": product, "version": m.group(1)})
        except Exception:
            pass
    return found


def query_nvd(product: str, version: str) -> list[dict]:
    NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    KW  = {"nginx": "nginx", "Apache": "apache http server", "PHP": "php",
            "WordPress": "wordpress", "Drupal": "drupal", "IIS": "microsoft iis"}
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
    contact  = discover_contact_email(domain)
    return {
        "domain":        domain,
        "country":       country,
        "software":      software,
        "cves":          cves[:5],
        "max_cvss":      max_cvss,
        "priority":      priority,
        "contact_email": contact,
    }


# ── Claude email generation ───────────────────────────────────────────────────

def generate_email_body(prospect: dict) -> str:
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
    db   = get_db()
    pid  = hashlib.sha256(p["domain"].encode()).hexdigest()[:16]
    now  = datetime.now(timezone.utc).isoformat()
    existing = db.table("outreach_prospects").select("id,status").eq("domain", p["domain"]).execute()

    update_data = {
        "software":      json.dumps(p["software"]),
        "cves":          json.dumps(p["cves"]),
        "max_cvss":      p["max_cvss"],
        "priority":      p["priority"],
        "contact_email": p.get("contact_email", f"security@{p['domain']}"),
        "scanned_at":    now,
    }

    if existing.data:
        row = existing.data[0]
        if row["status"] in ("approved", "sent"):
            # Don't reset approved/sent — just refresh scan data
            db.table("outreach_prospects").update(update_data).eq("id", row["id"]).execute()
            return
        db.table("outreach_prospects").update({
            **update_data,
            "email_body": email_body,
            "status":     "pending",
        }).eq("id", row["id"]).execute()
    else:
        db.table("outreach_prospects").insert({
            "id":            pid,
            "domain":        p["domain"],
            "country":       p["country"],
            "email_body":    email_body,
            "status":        "pending",
            **update_data,
        }).execute()


# ── Background scan job ───────────────────────────────────────────────────────

def _run_scan_job():
    """Daily job: fetch top 500 domains per country, passive scan, upsert prospects."""
    import urllib3
    urllib3.disable_warnings()
    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_domains = []
    for country in COUNTRY_TLDS:
        domains = fetch_country_domains(country, limit=SCAN_LIMIT)
        for d in domains:
            all_domains.append((d, country))

    print(f"[outreach] Starting scan: {len(all_domains)} domains across {len(COUNTRY_TLDS)} countries")
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
                    print(f"[outreach] ✓ {result['domain']} — CVSS {result['max_cvss']}")
            except Exception as e:
                domain, _ = futures[future]
                print(f"[outreach] ✗ {domain}: {e}")

    print(f"[outreach] Scan complete — {found} vulnerable domains found")

    try:
        db = get_db()
        db.table("outreach_log").insert({
            "event":     "daily_scan",
            "prospects": found,
            "ran_at":    datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception:
        pass


# ── API endpoints ─────────────────────────────────────────────────────────────

class EmailUpdate(BaseModel):
    email_body: str

class BulkApprove(BaseModel):
    ids: list[str]


def require_admin(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing auth")
    token = authorization.split(" ")[1]
    db     = get_db()
    result = db.table("sessions").select("user_id").eq("token", token).execute()
    if not result.data:
        raise HTTPException(401, "Invalid session")
    admin_email = os.getenv("ADMIN_EMAIL", "")
    if admin_email:
        user = db.table("users").select("email").eq("id", result.data[0]["user_id"]).execute()
        if not user.data or user.data[0]["email"] != admin_email:
            raise HTTPException(403, "Admin only")


@router.post("/run-scan")
async def run_scan(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Trigger prospect scan manually. Auto-runs at 06:00 daily."""
    require_admin(authorization)
    background_tasks.add_task(_run_scan_job)
    total = sum(len(fetch_country_domains(c, 1)) for c in COUNTRY_TLDS)  # quick check
    return {
        "status": "scan started",
        "countries": len(COUNTRY_TLDS),
        "scan_limit_per_country": SCAN_LIMIT,
        "source": "cloudflare_radar" if CLOUDFLARE_TOKEN else "tranco+fallback",
    }


@router.get("/prospects/stats")
async def prospects_stats(authorization: str = Header(None)):
    """Per-country breakdown: count, top CVSS, last scanned."""
    require_admin(authorization)
    db = get_db()
    rows = db.table("outreach_prospects").select("country,status,max_cvss,scanned_at").execute()

    stats: dict = {}
    last_scan = None
    for r in (rows.data or []):
        c = r.get("country", "??")
        if c not in stats:
            stats[c] = {"country": c, "total": 0, "pending": 0, "approved": 0,
                        "sent": 0, "skipped": 0, "top_cvss": 0, "last_scanned": None}
        stats[c]["total"] += 1
        stats[c][r.get("status", "pending")] = stats[c].get(r.get("status", "pending"), 0) + 1
        if (r.get("max_cvss") or 0) > stats[c]["top_cvss"]:
            stats[c]["top_cvss"] = r.get("max_cvss", 0)
        if r.get("scanned_at"):
            if not stats[c]["last_scanned"] or r["scanned_at"] > stats[c]["last_scanned"]:
                stats[c]["last_scanned"] = r["scanned_at"]
            if not last_scan or r["scanned_at"] > last_scan:
                last_scan = r["scanned_at"]

    # Last scan log entry
    try:
        log = db.table("outreach_log").select("ran_at").eq("event", "daily_scan")\
            .order("ran_at", desc=True).limit(1).execute()
        if log.data:
            last_scan = log.data[0]["ran_at"]
    except Exception:
        pass

    return {
        "countries":  sorted(stats.values(), key=lambda x: x["total"], reverse=True),
        "last_scan":  last_scan,
        "total":      sum(s["total"] for s in stats.values()),
        "source":     "cloudflare_radar" if CLOUDFLARE_TOKEN else "tranco+fallback",
        "scan_limit": SCAN_LIMIT,
    }


@router.get("/prospects")
async def list_prospects(
    status:      str   = "pending",
    country:     str   = "",
    min_cvss:    float = 0,
    limit:       int   = 200,
    authorization: str = Header(None),
):
    """List prospects sorted by CVSS. Filter by status/country/min_cvss."""
    require_admin(authorization)
    db = get_db()
    q  = db.table("outreach_prospects").select("*")
    if status != "all":
        q = q.eq("status", status)
    if country:
        q = q.eq("country", country)
    if min_cvss > 0:
        q = q.gte("max_cvss", min_cvss)
    result = q.order("max_cvss", desc=True).limit(limit).execute()

    rows = []
    for r in (result.data or []):
        rows.append({
            **r,
            "software": json.loads(r["software"]) if isinstance(r["software"], str) else (r["software"] or []),
            "cves":     json.loads(r["cves"]) if isinstance(r["cves"], str) else (r["cves"] or []),
        })
    return {"prospects": rows, "total": len(rows)}


@router.patch("/prospects/{prospect_id}/email")
async def update_email(prospect_id: str, body: EmailUpdate, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    db.table("outreach_prospects").update({
        "email_body": body.email_body,
        "edited":     True,
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
    """Send all approved emails. Respects OUTREACH_DAILY_LIMIT."""
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
        to_email   = row.get("contact_email") or f"security@{domain}"

        lines   = email_body.strip().splitlines()
        subject = f"Security vulnerability detected on {domain}"
        body    = email_body
        if lines and lines[0].lower().startswith("subject:"):
            subject = lines[0][8:].strip()
            body    = "\n".join(lines[2:]).strip()

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

        time.sleep(0.3)

    print(f"[outreach] sent {sent} emails")


def _text_to_html(text: str, domain: str) -> str:
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
    """Call from main.py startup to enable automatic daily scans."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        scheduler = BackgroundScheduler(timezone="Europe/Prague")
        scheduler.add_job(_run_scan_job, "cron", hour=6, minute=0, id="daily_prospect_scan")
        scheduler.start()
        source = "Cloudflare Radar" if CLOUDFLARE_TOKEN else "Tranco+fallback"
        print(f"[outreach] Daily scan scheduler started — 06:00 Prague, {len(COUNTRY_TLDS)} countries × {SCAN_LIMIT} domains ({source})")
        return scheduler
    except ImportError:
        print("[outreach] APScheduler not installed — add apscheduler to requirements.txt")
        return None
