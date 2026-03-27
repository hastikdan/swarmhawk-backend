"""
outreach.py — SwarmHawk Automated Prospect Intelligence Engine
==============================================================

Fully automated daily pipeline:
  1. 06:00 Prague → APScheduler fires _run_scan_job()
  2. fetch_country_domains() pulls top 500 domains per country:
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
PORTKEY_API_KEY     = os.getenv("PORTKEY_API_KEY", "")
FROM_EMAIL          = os.getenv("OUTREACH_FROM", "onboarding@resend.dev")
FROM_NAME           = "SwarmHawk Security"
CVSS_THRESHOLD      = float(os.getenv("OUTREACH_CVSS_MIN", "7.0"))
DAILY_SEND_LIMIT    = int(os.getenv("OUTREACH_DAILY_LIMIT", "20"))
CLOUDFLARE_TOKEN    = os.getenv("CLOUDFLARE_API_TOKEN", "")
SCAN_LIMIT          = int(os.getenv("OUTREACH_SCAN_LIMIT", "100"))  # domains per country
# Comma-separated country codes to scan, e.g. "CZ,SK,PL". Empty = all countries.
_OUTREACH_COUNTRIES_ENV = os.getenv("OUTREACH_COUNTRIES", "")
ACTIVE_COUNTRIES    = [c.strip().upper() for c in _OUTREACH_COUNTRIES_ENV.split(",") if c.strip()] if _OUTREACH_COUNTRIES_ENV else None
# Skip top-N most popular domains per country (they have big security teams, no CVEs).
# Set e.g. OUTREACH_RANK_OFFSET=500 to scan ranks 501-600 (mid-tier companies).
# Supports multiple brackets: "500,2000,10000" → scans SCAN_LIMIT from each bracket offset.
_RANK_OFFSET_ENV    = os.getenv("OUTREACH_RANK_OFFSET", "500")
RANK_OFFSETS        = [int(x.strip()) for x in _RANK_OFFSET_ENV.split(",") if x.strip()] if _RANK_OFFSET_ENV else [500]

TIMEOUT = 10
UA = {"User-Agent": "Mozilla/5.0 (compatible; SwarmHawk-Scout/1.0)"}


# ── Portkey-aware Anthropic call helper ───────────────────────────────────────

def _safe_json_list(val) -> list:
    """Safely parse a value that should be a JSON list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return []


def _anthropic_url() -> str:
    return "https://api.portkey.ai/v1/messages" if PORTKEY_API_KEY else "https://api.anthropic.com/v1/messages"

def _anthropic_headers(metadata: dict | None = None) -> dict:
    h = {
        "x-api-key": ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    if PORTKEY_API_KEY:
        h["x-portkey-api-key"]  = PORTKEY_API_KEY
        h["x-portkey-provider"] = "anthropic"
        if metadata:
            h["x-portkey-metadata"] = json.dumps(metadata)
    return h


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


def _get_tranco_domains(tld: str, limit: int, offset: int = 0) -> list[str]:
    """Download Tranco top-1M (cached 24 h) and filter by country TLD.
    `offset` skips the top-N most popular domains (e.g. offset=500 skips rank 1-500)."""
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
    tld_domains = [d for d in _tranco_cache["domains"] if d.endswith(tld)]
    return tld_domains[offset:offset + limit]


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
    Uses RANK_OFFSETS to skip most-popular domains and scan mid-tier brackets.
    Priority: Tranco TLD filter → hardcoded fallback."""
    # 1. Tranco list filtered by country TLD, using rank offsets
    tld = COUNTRY_TLDS.get(country_code, "")
    if tld:
        seen: set[str] = set()
        combined: list[str] = []
        per_bracket = max(1, limit // len(RANK_OFFSETS))
        for offset in RANK_OFFSETS:
            bracket = _get_tranco_domains(tld, per_bracket, offset)
            for d in bracket:
                if d not in seen:
                    seen.add(d)
                    combined.append(d)
        if combined:
            print(f"[tranco] {country_code}{tld}: {len(combined)} domains (offsets={RANK_OFFSETS})")
            return combined[:limit]

    # 2. Hardcoded fallback
    fallback = PROSPECT_DOMAINS.get(country_code, [])
    print(f"[fallback] {country_code}: {len(fallback)} domains (hardcoded)")
    return fallback[:limit]


# ── Contact email discovery ────────────────────────────────────────────────────

# Domains that commonly appear in HTML but are not real contact emails
_JUNK_EMAIL_DOMAINS = {
    "example.com", "sentry.io", "w3.org", "schema.org", "cloudflare.com",
    "googleapis.com", "gstatic.com", "jquery.com", "bootstrapcdn.com",
    "fonts.googleapis.com", "cdn.jsdelivr.net", "amazonaws.com",
    "wordpress.org", "placeholder.com", "yourdomain.com",
}
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# Pages to scrape for contact emails (EU-aware: impressum is legally required in DACH/CEE)
_CONTACT_PAGES = [
    "/", "/contact", "/contact-us", "/kontakt", "/impressum",
    "/imprint", "/about", "/about-us", "/datenschutz", "/privacy",
]


def _extract_emails_from_html(html: str, own_domain: str) -> list[str]:
    """Pull emails from raw HTML, filter junk, prefer own-domain addresses."""
    found = []
    seen: set[str] = set()
    for raw in _EMAIL_RE.findall(html):
        e = raw.strip().lower().rstrip(".")
        # Skip junk file extensions (CSS background-image, image files referenced as emails)
        if any(e.endswith(ext) for ext in (".png", ".jpg", ".gif", ".svg", ".css", ".js")):
            continue
        host = e.split("@")[1]
        if host in _JUNK_EMAIL_DOMAINS:
            continue
        if e not in seen:
            seen.add(e)
            found.append(e)
    # Own-domain addresses first
    own   = [e for e in found if e.endswith(f"@{own_domain}")]
    other = [e for e in found if not e.endswith(f"@{own_domain}")]
    return own + other


def discover_all_contacts(domain: str) -> list[str]:
    """
    Multi-source contact discovery.  Returns a deduplicated list of emails
    ranked best-first:

      1. security.txt  (RFC 9116 — most authoritative)
      2. WHOIS registrant / admin / tech contacts
      3. Website scrape: homepage + /contact, /impressum, /about …  (parallel)
      4. Common pattern guesses (security@, info@, …) as last resort

    All HTTP requests run in parallel — total wall time ~5-8s max.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    raw_verified: list[str] = []
    raw_guesses:  list[str] = []

    def _collect(emails: list[str], *, is_guess: bool = False):
        target = raw_guesses if is_guess else raw_verified
        target.extend(emails)

    def _fetch_security_txt() -> list[str]:
        found = []
        for path in ["/.well-known/security.txt", "/security.txt"]:
            try:
                r = req.get(f"https://{domain}{path}", timeout=5, headers=UA, verify=False)
                if r.status_code == 200 and "Contact:" in r.text:
                    for m in re.finditer(
                        r"Contact:\s*(?:mailto:)?([^\s]+@[^\s]+)", r.text, re.IGNORECASE
                    ):
                        found.append(m.group(1))
            except Exception:
                pass
        return found

    def _fetch_whois() -> list[str]:
        try:
            import whois
            w = whois.whois(domain)
            raw = w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
            return [str(e) for e in raw if e]
        except Exception:
            return []

    def _fetch_page(path: str) -> list[str]:
        try:
            r = req.get(
                f"https://{domain}{path}",
                timeout=5, headers=UA, verify=False, allow_redirects=True,
            )
            if r.status_code == 200:
                return _extract_emails_from_html(r.text[:80_000], domain)
        except Exception:
            pass
        return []

    # ── Run all sources in parallel (max 15s total wall time) ────────────────
    futures = {}
    with ThreadPoolExecutor(max_workers=14) as pool:
        futures["security_txt"] = pool.submit(_fetch_security_txt)
        futures["whois"]        = pool.submit(_fetch_whois)
        for path in _CONTACT_PAGES:
            futures[f"page:{path}"] = pool.submit(_fetch_page, path)

        for key, fut in futures.items():
            try:
                emails = fut.result(timeout=12)
                _collect(emails)
            except Exception:
                pass

    # ── 4. Pattern guesses (last resort) ─────────────────────────────────────
    for prefix in ["security", "info", "contact", "webmaster", "admin"]:
        raw_guesses.append(f"{prefix}@{domain}")

    # Deduplicate, filter junk, own-domain first
    seen: set[str] = set()
    result: list[str] = []

    def _clean_add(email: str):
        e = email.strip().lower().rstrip(".")
        if not e or "@" not in e:
            return
        host = e.split("@")[1]
        if "." not in host or host in _JUNK_EMAIL_DOMAINS:
            return
        if any(e.endswith(ext) for ext in (".png", ".jpg", ".gif", ".svg", ".css", ".js")):
            return
        if e not in seen:
            seen.add(e)
            result.append(e)

    # Own-domain verified addresses first, then other verified, then guesses
    own     = [e for e in raw_verified if f"@{domain}" in e.lower()]
    other   = [e for e in raw_verified if f"@{domain}" not in e.lower()]
    for e in own + other + raw_guesses:
        _clean_add(e)

    return result[:10]


def discover_contact_email(domain: str) -> str:
    """Best single contact email for a domain (backward-compatible wrapper)."""
    contacts = discover_all_contacts(domain)
    return contacts[0] if contacts else f"security@{domain}"


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


# Module-level NVD response cache — keyed by "product:version", TTL 24h.
# Eliminates repeated API calls for the same software across thousands of domains.
_NVD_CACHE: dict = {}
_NVD_CACHE_TTL = 86400  # seconds


def query_nvd(product: str, version: str) -> list[dict]:
    """Query NVD for CVEs matching product+version.

    Results are cached in-memory for 24h.  The same nginx/1.14 across 10,000
    domains produces exactly one NVD API call instead of 10,000.
    """
    cache_key = f"{product}:{version}"
    entry = _NVD_CACHE.get(cache_key)
    if entry and (time.time() - entry["ts"]) < _NVD_CACHE_TTL:
        return entry["data"]

    NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    KW  = {"nginx": "nginx", "Apache": "apache http server", "PHP": "php",
            "WordPress": "wordpress", "Drupal": "drupal", "IIS": "microsoft iis"}
    kw  = KW.get(product, product.lower())
    time.sleep(0.5)   # NVD rate limit (5 req/30s without API key)
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
        result = sorted(cves, key=lambda x: x["cvss"], reverse=True)
        _NVD_CACHE[cache_key] = {"data": result, "ts": time.time()}
        return result
    except Exception:
        _NVD_CACHE[cache_key] = {"data": [], "ts": time.time()}
        return []


def scan_domain_passive(domain: str, country: str) -> Optional[dict]:
    software = detect_software(domain)
    cves = []
    for sw in (software or []):
        if sw["version"] and sw["version"] != "unknown":
            cves.extend(query_nvd(sw["product"], sw["version"]))
    max_cvss = max((c["cvss"] for c in cves), default=0.0)
    if max_cvss >= 9:
        priority = "CRITICAL"
    elif max_cvss >= 7:
        priority = "HIGH"
    elif max_cvss >= 4:
        priority = "MEDIUM"
    elif max_cvss > 0:
        priority = "LOW"
    else:
        priority = "INFO"

    # Lightweight contact discovery for bulk scans — security.txt only + fallback.
    # Full multi-source discovery (WHOIS + scraping) runs on-demand per domain via
    # POST /domains/{id}/contacts/discover — never in the batch pipeline.
    contact = discover_contact_email(domain)
    return {
        "domain":         domain,
        "country":        country,
        "software":       software,
        "cves":           cves[:5],
        "max_cvss":       max_cvss,
        "priority":       priority,
        "contact_email":  contact,
        "contact_emails": [],   # populated later via on-demand discovery
    }


# ── Claude email generation ───────────────────────────────────────────────────

def generate_email_body(prospect: dict) -> str:
    if not ANTHROPIC_KEY:
        return _fallback_email(prospect)
    if not prospect.get("cves"):
        return _fallback_email(prospect)
    top_cve  = prospect["cves"][0]
    sw_list  = ", ".join(f"{s['product']} {s['version']}" for s in prospect["software"])
    cve_list = ", ".join(f"{c['id']} CVSS {c['cvss']}" for c in prospect["cves"][:3])
    country  = prospect.get("country", "")
    template = _get_country_template(country)
    try:
        prompt = template.format(
            domain=prospect["domain"],
            sw_list=sw_list,
            cve_list=cve_list,
            top_cve_id=top_cve["id"],
            top_cvss=top_cve["cvss"],
        )
    except KeyError:
        # Template uses unknown variables — fall back to default
        prompt = DEFAULT_TEMPLATE.format(
            domain=prospect["domain"],
            sw_list=sw_list,
            cve_list=cve_list,
            top_cve_id=top_cve["id"],
            top_cvss=top_cve["cvss"],
        )
    try:
        r = req.post(
            _anthropic_url(),
            headers=_anthropic_headers({"report_type": "outreach_email", "domain": prospect["domain"], "_user": "system"}),
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
    cves = p.get("cves") or []
    sw   = (p.get("software") or [{}])[0]
    if cves:
        top = cves[0]
        return (
            f"Subject: Security vulnerability detected on {p['domain']} — {top['id']} CVSS {top['cvss']}\n\n"
            f"Dear {p['domain']} team,\n\n"
            f"Our automated security scanner detected {top['id']} (CVSS {top['cvss']}) "
            f"on your server running {sw.get('product','your server')} {sw.get('version','')}. "
            f"This is a publicly known vulnerability that could expose your organisation "
            f"to data breaches and NIS2 compliance penalties.\n\n"
            f"We have prepared a free full security report for {p['domain']} including "
            f"exact findings and remediation steps. Visit swarmhawk.com or reply to this "
            f"email to access it.\n\n"
            f"The SwarmHawk Team | swarmhawk.com"
        )
    else:
        sw_line = f" running {sw.get('product','')} {sw.get('version','')}".strip() if sw.get('product') else ""
        return (
            f"Subject: Free security scan available for {p['domain']}\n\n"
            f"Dear {p['domain']} team,\n\n"
            f"SwarmHawk's automated scanner reviewed {p['domain']}{sw_line} as part of our "
            f"NIS2 compliance monitoring programme. No critical vulnerabilities were detected today, "
            f"however our full 22-point security audit covers SSL, email security, exposed services, "
            f"source code exposure and more.\n\n"
            f"We have a free detailed report available for {p['domain']}. "
            f"Visit swarmhawk.com or reply to claim it.\n\n"
            f"The SwarmHawk Team | swarmhawk.com"
        )


# ── Supabase helpers ──────────────────────────────────────────────────────────

def get_db():
    """Use service_role key so queries work after RLS deny-all is enabled."""
    from supabase import create_client
    key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")
    return create_client(os.getenv("SUPABASE_URL"), key)


def upsert_prospect(p: dict, email_body: str, db=None):
    db = db or get_db()
    pid  = hashlib.sha256(p["domain"].encode()).hexdigest()[:16]
    now  = datetime.now(timezone.utc).isoformat()
    existing = db.table("outreach_prospects").select("id,status").eq("domain", p["domain"]).execute()

    # Honour primary_contact set by a SwarmHawk user for this domain (overrides auto-detected)
    contact_email = p.get("contact_email", f"security@{p['domain']}")
    try:
        dom_row = db.table("domains").select("primary_contact").eq("domain", p["domain"]).execute()
        if dom_row.data and dom_row.data[0].get("primary_contact"):
            contact_email = dom_row.data[0]["primary_contact"]
    except Exception:
        pass

    update_data = {
        "software":        json.dumps(p["software"]),
        "cves":            json.dumps(p["cves"]),
        "max_cvss":        p["max_cvss"],
        "priority":        p["priority"],
        "contact_email":   contact_email,
        "contact_emails":  json.dumps(p.get("contact_emails", [])),
        "scanned_at":      now,
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


# ── Scan progress state (in-memory, updated by _run_scan_job) ─────────────────
_scan_progress: dict = {"status": "idle"}
_stop_requested: bool = False


# ── Background scan job ───────────────────────────────────────────────────────

def _run_scan_job():
    """Scan top SCAN_LIMIT domains per country in parallel across all (or configured) countries."""
    global _scan_progress, _stop_requested
    _stop_requested = False
    import urllib3
    urllib3.disable_warnings()
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Honour OUTREACH_COUNTRIES env var — restrict to listed countries if set
    countries_to_scan = {k: v for k, v in COUNTRY_TLDS.items() if not ACTIVE_COUNTRIES or k in ACTIVE_COUNTRIES}
    if not countries_to_scan:
        print(f"[outreach] OUTREACH_COUNTRIES={ACTIVE_COUNTRIES} matched no known countries — aborting")
        return

    _scan_progress = {
        "status":        "fetching",
        "phase":         f"Fetching domain lists for {len(countries_to_scan)} country/countries in parallel…",
        "started_at":    datetime.now(timezone.utc).isoformat(),
        "total":         0,
        "scanned":       0,
        "found":         0,
        "country_stats": {},
        "finished_at":   None,
    }

    found = 0
    try:
        # ── Phase 1: fetch all country domain lists in parallel ──────────────
        country_domains: dict[str, list[str]] = {}

        def _fetch_country(country):
            return country, fetch_country_domains(country, limit=SCAN_LIMIT)

        with ThreadPoolExecutor(max_workers=max(1, len(countries_to_scan))) as ex:
            for country, domains in ex.map(_fetch_country, countries_to_scan.keys()):
                if domains:
                    country_domains[country] = domains

        all_domains = [(d, c) for c, doms in country_domains.items() for d in doms]
        total = len(all_domains)

        # ── Phase 2: scan all domains across all countries in parallel ────────
        _scan_progress.update({
            "status":  "running",
            "phase":   f"Scanning {total} domains across {len(country_domains)} countries…",
            "total":   total,
            "country_stats": {
                c: {"total": len(doms), "scanned": 0, "found": 0}
                for c, doms in country_domains.items()
            },
        })

        print(f"[outreach] Starting scan: {total} domains across {len(country_domains)} countries "
              f"({SCAN_LIMIT}/country)")

        db = get_db()  # single shared connection for all upserts

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(scan_domain_passive, domain, country): (domain, country)
                       for domain, country in all_domains}
            for future in as_completed(futures):
                domain, country = futures[future]
                if _stop_requested:
                    print(f"[outreach] Stop requested — cancelling remaining futures")
                    for f in futures:
                        f.cancel()
                    break
                _scan_progress["scanned"] += 1
                _scan_progress["country_stats"][country]["scanned"] += 1
                try:
                    result = future.result()
                    if result:
                        # AI-draft for critical CVE threats (CVSS ≥ 8); fallback for others.
                        if result["max_cvss"] >= 8.0 and result.get("cves") and ANTHROPIC_KEY:
                            email_body = generate_email_body(result)
                        else:
                            email_body = _fallback_email(result)
                        upsert_prospect(result, email_body, db=db)
                        # Dual-write to unified scan_results (Phase 1 pipeline)
                        try:
                            from pipeline import upsert_scan_result
                            upsert_scan_result({**result, "email_body": email_body, "source": "outreach"}, db=db)
                        except Exception:
                            pass
                        found += 1
                        _scan_progress["found"]  += 1
                        _scan_progress["country_stats"][country]["found"] += 1
                        print(f"[outreach] ✓ {result['domain']} — CVSS {result['max_cvss']}")
                except Exception as e:
                    print(f"[outreach] ✗ {domain}: {e}")

        try:
            db.table("outreach_log").insert({
                "event":     "daily_scan",
                "prospects": found,
                "ran_at":    datetime.now(timezone.utc).isoformat(),
            }).execute()
        except Exception:
            pass

    except Exception as e:
        print(f"[outreach] Scan job crashed: {e}")
        _scan_progress.update({
            "status":      "done",
            "phase":       f"Scan interrupted — {found} prospects saved before error",
            "found":       found,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        })
        return

    if _stop_requested:
        print(f"[outreach] Scan stopped by admin — {found} vulnerable domains saved")
        _scan_progress.update({
            "status":      "done",
            "phase":       f"Stopped — {found} vulnerable domains saved before stop",
            "found":       found,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        })
    else:
        print(f"[outreach] Scan complete — {found} vulnerable domains found")
        _scan_progress.update({
            "status":      "done",
            "phase":       f"Complete — {found} vulnerable domains found",
            "found":       found,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        })

    # ── Phase 3: sync user-set contacts → outreach_prospects ─────────────────
    # Any domain in the `domains` table that has a primary_contact set should
    # have that contact reflected in the outreach_prospects row for the same domain.
    # This runs after every daily batch so manually-added contacts propagate
    # to Marketing without waiting for the next domain re-scan.
    _sync_domain_contacts_to_prospects(db)

    # ── Phase 4: send daily digest to admin ───────────────────────────────────
    send_admin_digest(found, db=db)

    # Bust the threat map cache so next /map/data request rebuilds from fresh data
    try:
        import main as _main
        _main._map_cache["data"] = None
    except Exception:
        pass


def _sync_domain_contacts_to_prospects(db=None):
    """Sync primary_contact and contact_emails from domains table → outreach_prospects.
    Called after every daily scan batch. Safe to call at any time."""
    db = db or get_db()
    synced = 0
    try:
        # Fetch all domains that have a primary_contact set
        rows = db.table("domains")\
                 .select("domain,primary_contact,contact_emails")\
                 .not_.is_("primary_contact", "null")\
                 .neq("primary_contact", "")\
                 .execute()
        if not rows.data:
            print("[outreach] contact sync: no domains with primary_contact set")
            return

        for d in rows.data:
            domain          = d.get("domain", "")
            primary_contact = d.get("primary_contact", "").strip()
            raw_emails      = d.get("contact_emails") or "[]"
            if not domain or not primary_contact:
                continue

            # Parse the full email list
            try:
                emails_list = json.loads(raw_emails) if isinstance(raw_emails, str) else (raw_emails or [])
            except Exception:
                emails_list = []
            # Ensure primary is in list
            if primary_contact not in emails_list:
                emails_list.insert(0, primary_contact)

            # Only update outreach_prospects where this domain exists
            prospect = db.table("outreach_prospects")\
                         .select("id,contact_email")\
                         .eq("domain", domain)\
                         .execute()
            if not prospect.data:
                continue

            current = prospect.data[0].get("contact_email", "")
            # Only overwrite if user-set contact differs (don't stomp manually edited outreach contacts)
            if current != primary_contact:
                db.table("outreach_prospects").update({
                    "contact_email":  primary_contact,
                    "contact_emails": json.dumps(emails_list),
                }).eq("domain", domain).execute()
                synced += 1

        print(f"[outreach] contact sync: updated {synced}/{len(rows.data)} prospect contact(s)")
    except Exception as e:
        print(f"[outreach] contact sync error: {e}")


# ── Admin daily digest ────────────────────────────────────────────────────────

def send_admin_digest(found_count: int, db=None):
    """Email the admin a daily summary: new prospects found, top 10 by CVSS, pending count."""
    if not RESEND_API_KEY:
        print("[outreach] digest: RESEND_API_KEY not set — skipping")
        return
    admin_email = os.getenv("ADMIN_EMAIL", "hastikdan@gmail.com")
    db = db or get_db()

    # Fetch top prospects by CVSS (all-time, not just today — so digest is never empty)
    # Also count how many were scanned today specifically
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        top_rows = (
            db.table("outreach_prospects")
            .select("domain,country,max_cvss,status,contact_email,scanned_at")
            .order("max_cvss", desc=True)
            .limit(10)
            .execute()
        )
        top = top_rows.data or []
    except Exception as e:
        print(f"[outreach] digest: DB error {e}")
        top = []

    # Count prospects scanned today (separate from found_count which is this run's new finds)
    try:
        today_rows = (
            db.table("outreach_prospects")
            .select("id", count="exact")
            .gte("scanned_at", today)
            .execute()
        )
        today_count = today_rows.count or 0
    except Exception:
        today_count = found_count

    # Fetch pending count
    try:
        pending_count = (
            db.table("outreach_prospects")
            .select("id", count="exact")
            .eq("status", "pending")
            .execute()
            .count or 0
        )
    except Exception:
        pending_count = "?"

    site = os.getenv("SITE_URL", "https://www.swarmhawk.com")

    rows_html = ""
    for r in top:
        cvss = r.get("max_cvss", 0) or 0
        color = "#E74C3C" if cvss >= 9 else "#E67E22" if cvss >= 7 else "#888"
        status     = r.get("status", "pending")
        sbg        = "rgba(26,122,74,.2)"  if status == "approved" else "rgba(212,133,10,.2)"
        scolor     = "#2ECC71"             if status == "approved" else "#E67E22"
        domain     = r.get("domain", "")
        country    = r.get("country", "")
        contact    = r.get("contact_email", "")
        rows_html += (
            f"<tr>"
            f"<td style='padding:6px 10px;font-family:monospace;font-size:13px'>{domain}</td>"
            f"<td style='padding:6px 10px;text-align:center'>{country}</td>"
            f"<td style='padding:6px 10px;text-align:center;color:{color};font-weight:700'>{cvss}</td>"
            f"<td style='padding:6px 10px;font-size:11px;color:#888'>{contact}</td>"
            f"<td style='padding:6px 10px;text-align:center'>"
            f"<span style='font-size:10px;padding:2px 8px;border-radius:8px;"
            f"background:{sbg};color:{scolor}'>{status.upper()}</span>"
            f"</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;font-size:14px;color:#222;max-width:650px;margin:0 auto;padding:24px;background:#f9f9f9">
  <div style="background:#0E0D12;padding:18px 24px;border-radius:10px 10px 0 0;display:flex;align-items:center;gap:12px">
    <strong style="font-family:monospace;font-size:16px;color:#0E0D12;background:#CBFF00;padding:4px 10px">SWARMHAWK</strong>
    <span style="color:#888;font-size:13px">Daily Outreach Digest</span>
  </div>
  <div style="background:#fff;border:1px solid #eee;border-top:none;padding:24px;border-radius:0 0 10px 10px">
    <h2 style="margin:0 0 16px 0;font-size:18px">📣 Daily Scan Complete</h2>
    <div style="display:flex;gap:24px;margin-bottom:20px">
      <div style="text-align:center;background:#f5f5f5;border-radius:8px;padding:14px 20px">
        <div style="font-size:28px;font-weight:700;color:#E74C3C">{today_count}</div>
        <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Scanned Today</div>
      </div>
      <div style="text-align:center;background:#f5f5f5;border-radius:8px;padding:14px 20px">
        <div style="font-size:28px;font-weight:700;color:#E74C3C">{found_count}</div>
        <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">New Vulnerable</div>
      </div>
      <div style="text-align:center;background:#f5f5f5;border-radius:8px;padding:14px 20px">
        <div style="font-size:28px;font-weight:700;color:#E67E22">{pending_count}</div>
        <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Pending Review</div>
      </div>
    </div>
    {"<h3 style='font-size:14px;margin:0 0 10px 0'>Top " + str(len(top)) + " by CVSS (all-time)</h3><table style='width:100%;border-collapse:collapse;font-size:13px'><thead><tr style='background:#f5f5f5'><th style='padding:6px 10px;text-align:left'>Domain</th><th style='padding:6px 10px'>Country</th><th style='padding:6px 10px'>CVSS</th><th style='padding:6px 10px'>Contact</th><th style='padding:6px 10px'>Status</th></tr></thead><tbody>" + rows_html + "</tbody></table>" if top else "<p style='color:#888'>No prospects in database yet.</p>"}
    <div style="margin-top:24px;text-align:center">
      <a href="{site}?admin=1#marketing" style="display:inline-block;background:#CBFF00;color:#0E0D12;font-weight:700;font-family:monospace;padding:12px 28px;border-radius:6px;text-decoration:none;font-size:14px">▸ Open Marketing Dashboard</a>
    </div>
    <p style="font-size:11px;color:#aaa;margin-top:20px;text-align:center">
      SwarmHawk automated digest · Sent after daily 08:00 scan · <a href="{site}" style="color:#aaa">swarmhawk.com</a>
    </p>
  </div>
</body></html>"""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        r = req.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={
                "from":    f"{FROM_NAME} <{FROM_EMAIL}>",
                "to":      [admin_email],
                "subject": f"[SwarmHawk] Daily Digest — {found_count} new prospects · {now}",
                "html":    html,
            },
            timeout=15,
        )
        if r.status_code in (200, 201):
            print(f"[outreach] digest sent → {admin_email}")
        else:
            print(f"[outreach] digest Resend error {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[outreach] digest error: {e}")


# ── API endpoints ─────────────────────────────────────────────────────────────

class EmailUpdate(BaseModel):
    email_body: str

class BulkApprove(BaseModel):
    ids: list[str]

class ScheduleRequest(BaseModel):
    domains: list[str]
    scheduled_for: str   # ISO date string e.g. "2026-03-15"


def require_admin(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing auth")
    token = authorization.split(" ")[1]
    db     = get_db()
    result = db.table("sessions").select("user_id").eq("token", token).execute()
    if not result.data:
        raise HTTPException(401, "Invalid session")
    admin_email = os.getenv("ADMIN_EMAIL", "hastikdan@gmail.com")
    user = db.table("users").select("email").eq("id", result.data[0]["user_id"]).execute()
    if not user.data or user.data[0]["email"] != admin_email:
        raise HTTPException(403, "Admin only")


@router.post("/run-scan")
async def run_scan(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Trigger prospect scan manually. Auto-runs at 06:00 daily."""
    require_admin(authorization)
    if _scan_progress.get("status") == "running":
        return {"status": "already_running", **_scan_progress}
    background_tasks.add_task(_run_scan_job)
    active = {k: v for k, v in COUNTRY_TLDS.items() if not ACTIVE_COUNTRIES or k in ACTIVE_COUNTRIES}
    return {
        "status": "scan started",
        "countries": len(active),
        "active_countries": list(active.keys()),
        "scan_limit_per_country": SCAN_LIMIT,
        "source": "cloudflare_radar" if CLOUDFLARE_TOKEN else "tranco+fallback",
    }


@router.post("/internal/cron")
async def internal_cron_trigger(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Trigger daily scan via a static CRON_SECRET — for GitHub Actions / external schedulers.
    Bypasses session auth so it works even when the Render dyno was sleeping."""
    secret = os.getenv("CRON_SECRET", "")
    if not secret:
        raise HTTPException(503, "CRON_SECRET not configured on server")
    if not authorization or authorization != f"Bearer {secret}":
        raise HTTPException(401, "Invalid cron secret")
    if _scan_progress.get("status") == "running":
        return {"status": "already_running", **_scan_progress}
    background_tasks.add_task(_run_scan_job)
    active = {k: v for k, v in COUNTRY_TLDS.items() if not ACTIVE_COUNTRIES or k in ACTIVE_COUNTRIES}
    return {
        "status": "scan started",
        "triggered_by": "cron",
        "countries": len(active),
        "scan_limit_per_country": SCAN_LIMIT,
    }


@router.post("/stop-scan")
async def stop_scan(authorization: str = Header(None)):
    """Request the running scan to stop after the current batch."""
    require_admin(authorization)
    global _stop_requested
    if _scan_progress.get("status") not in ("running", "fetching"):
        return {"status": "not_running"}
    _stop_requested = True
    return {"status": "stop_requested", "saved_so_far": _scan_progress.get("found", 0)}


@router.post("/sync-contacts")
async def sync_contacts(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Manually trigger contact sync: domain primary_contact → outreach_prospects.
    Runs automatically after every daily scan. Use this to sync immediately after
    adding contacts in the Domains tab without waiting for next batch."""
    require_admin(authorization)
    background_tasks.add_task(_sync_domain_contacts_to_prospects)
    return {"status": "sync started — domain contacts propagating to Marketing prospects"}


@router.post("/digest")
async def trigger_digest(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Manually send admin daily digest email."""
    require_admin(authorization)
    db = get_db()
    try:
        pending_count = (
            db.table("outreach_prospects")
            .select("id", count="exact")
            .eq("status", "pending")
            .execute()
            .count or 0
        )
    except Exception:
        pending_count = 0
    background_tasks.add_task(send_admin_digest, pending_count)
    return {"status": "digest sending"}


def _draft_pending_job():
    """AI-draft emails for all pending prospects that have only a fallback email."""
    if not ANTHROPIC_KEY:
        print("[outreach] draft-pending: ANTHROPIC_KEY not set")
        return
    db = get_db()
    rows = (
        db.table("outreach_prospects")
        .select("*")
        .eq("status", "pending")
        .execute()
    )
    drafted = 0
    skipped = 0
    for row in (rows.data or []):
        # Skip already AI-drafted (edited flag or email has more than 4 lines)
        email_body = row.get("email_body") or ""
        if row.get("edited"):
            skipped += 1
            continue
        # Build a minimal prospect dict for generate_email_body
        try:
            software = json.loads(row["software"]) if isinstance(row.get("software"), str) else (row.get("software") or [])
            cves     = json.loads(row["cves"])     if isinstance(row.get("cves"), str)     else (row.get("cves") or [])
        except Exception:
            skipped += 1
            continue
        if not software:
            skipped += 1
            continue
        prospect = {
            "domain":    row["domain"],
            "country":   row.get("country", ""),
            "software":  software,
            "cves":      cves,
            "max_cvss":  row.get("max_cvss", 0),
        }
        new_body = generate_email_body(prospect)
        db.table("outreach_prospects").update({"email_body": new_body}).eq("id", row["id"]).execute()
        drafted += 1
        print(f"[outreach] AI-drafted → {row['domain']}")

    print(f"[outreach] draft-pending: {drafted} drafted, {skipped} skipped")


@router.post("/draft-pending")
async def draft_pending(background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """AI-generate emails for all pending prospects that don't have a custom email yet."""
    require_admin(authorization)
    background_tasks.add_task(_draft_pending_job)
    return {"status": "drafting started — AI emails generating in background"}


@router.get("/scan-progress")
async def get_scan_progress(authorization: str = Header(None)):
    """Return real-time scan progress. Poll this while a scan is running."""
    require_admin(authorization)
    p = dict(_scan_progress)
    # Compute elapsed + ETA
    if p.get("started_at") and p.get("status") in ("running", "fetching", "done"):
        try:
            started = datetime.fromisoformat(p["started_at"])
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            p["elapsed_s"] = int(elapsed)
            scanned = p.get("scanned", 0)
            total   = p.get("total", 0)
            if scanned > 10 and total > scanned:
                rate      = scanned / elapsed          # domains/sec
                remaining = total - scanned
                p["eta_s"] = int(remaining / rate)
            else:
                p["eta_s"] = None
        except Exception:
            p["elapsed_s"] = 0
            p["eta_s"]     = None
    return p


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

    # Count prospects whose scanned_at is today (UTC date)
    today = datetime.now(timezone.utc).date().isoformat()
    scanned_today = 0
    try:
        today_rows = db.table("outreach_prospects")\
            .select("id", count="exact")\
            .gte("scanned_at", today)\
            .execute()
        scanned_today = today_rows.count or 0
    except Exception:
        pass

    return {
        "countries":     sorted(stats.values(), key=lambda x: x["total"], reverse=True),
        "last_scan":     last_scan,
        "scanned_today": scanned_today,
        "total":         sum(s["total"] for s in stats.values()),
        "source":        "cloudflare_radar" if CLOUDFLARE_TOKEN else "tranco+fallback",
        "scan_limit":    SCAN_LIMIT,
    }


@router.get("/prospects")
async def list_prospects(
    status:        str   = "pending",
    country:       str   = "",
    min_cvss:      float = 0,
    limit:         int   = 200,
    page:          int   = 1,
    per_page:      int   = 0,    # if set, overrides limit and enables pagination
    authorization: str   = Header(None),
):
    """List prospects sorted by CVSS. Reads scan_results as primary source,
    supplements with outreach_prospects for legacy data not yet in scan_results."""
    require_admin(authorization)
    db = get_db()
    rows = []

    # ── Primary: scan_results (pipeline data) ────────────────────────────────
    try:
        q = db.table("scan_results").select("*")
        if status != "all":
            q = q.eq("outreach_status", status)
        else:
            q = q.not_.is_("outreach_status", "null")
        if country:
            q = q.eq("country", country)
        if min_cvss > 0:
            q = q.gte("max_cvss", min_cvss)
        sr_result = q.order("max_cvss", desc=True).limit(limit).execute()
        sr_domains: set[str] = set()
        for r in (sr_result.data or []):
            sr_domains.add(r["domain"])
            rows.append({
                **r,
                "status":   r.get("outreach_status"),
                "software": _safe_json_list(r.get("software")),
                "cves":     _safe_json_list(r.get("cves")),
                "_source":  "scan_results",
            })
    except Exception as e:
        log.warning(f"[prospects] scan_results query failed: {e}")
        sr_domains = set()

    # ── Supplement: outreach_prospects (legacy, not yet in scan_results) ─────
    remaining = limit - len(rows)
    if remaining > 0:
        try:
            q2 = db.table("outreach_prospects").select("*")
            if status != "all":
                q2 = q2.eq("status", status)
            if country:
                q2 = q2.eq("country", country)
            if min_cvss > 0:
                q2 = q2.gte("max_cvss", min_cvss)
            op_result = q2.order("max_cvss", desc=True).limit(remaining + len(sr_domains)).execute()
            for r in (op_result.data or []):
                if r["domain"] not in sr_domains:
                    rows.append({
                        **r,
                        "software": _safe_json_list(r.get("software")),
                        "cves":     _safe_json_list(r.get("cves")),
                        "_source":  "outreach_prospects",
                    })
                    if len(rows) >= limit:
                        break
        except Exception as e:
            log.warning(f"[prospects] outreach_prospects fallback failed: {e}")

    rows.sort(key=lambda r: float(r.get("max_cvss") or 0), reverse=True)

    total = len(rows)
    if per_page > 0:
        start = (page - 1) * per_page
        rows  = rows[start:start + per_page]
    else:
        rows  = rows[:limit]
    return {"prospects": rows, "total": total}


def _prospect_update(db, prospect_id: str, sr_data: dict, op_data: dict):
    """Update prospect by id — tries scan_results first, falls back to outreach_prospects."""
    try:
        res = db.table("scan_results").update(sr_data).eq("id", prospect_id).execute()
        if res.data:
            return
    except Exception:
        pass
    try:
        db.table("outreach_prospects").update(op_data).eq("id", prospect_id).execute()
    except Exception:
        pass


@router.patch("/prospects/{prospect_id}/email")
async def update_email(prospect_id: str, body: EmailUpdate, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    _prospect_update(db, prospect_id,
        sr_data={"email_body": body.email_body, "edited": True},
        op_data={"email_body": body.email_body, "edited": True},
    )
    return {"status": "saved"}


@router.patch("/prospects/{prospect_id}/contact")
async def update_contact(prospect_id: str, body: dict, authorization: str = Header(None)):
    """Update the send-to contact email for a prospect."""
    require_admin(authorization)
    email = (body.get("contact_email") or "").strip()
    if not email or "@" not in email:
        raise HTTPException(400, "Invalid email")
    db = get_db()
    _prospect_update(db, prospect_id,
        sr_data={"contact_email": email},
        op_data={"contact_email": email},
    )
    return {"status": "saved", "contact_email": email}


@router.post("/prospects/{prospect_id}/approve")
async def approve_prospect(prospect_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    _prospect_update(db, prospect_id,
        sr_data={"outreach_status": "approved", "approved_at": now},
        op_data={"status": "approved", "approved_at": now},
    )
    return {"status": "approved"}


@router.post("/prospects/{prospect_id}/skip")
async def skip_prospect(prospect_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    _prospect_update(db, prospect_id,
        sr_data={"outreach_status": "skipped"},
        op_data={"status": "skipped"},
    )
    return {"status": "skipped"}


@router.post("/prospects/{prospect_id}/send")
async def send_single_prospect(prospect_id: str, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    """Send email to a single approved prospect immediately."""
    require_admin(authorization)
    if not RESEND_API_KEY:
        raise HTTPException(503, "RESEND_API_KEY not configured")
    db = get_db()

    # Fetch from scan_results first, fallback to outreach_prospects
    row = None
    try:
        r = db.table("scan_results").select("*").eq("id", prospect_id).limit(1).execute()
        if r.data:
            row = r.data[0]
            domain     = row["domain"]
            email_body = row.get("email_draft") or row.get("email_body") or ""
            to_email   = row.get("contact_email") or f"security@{domain}"
    except Exception:
        pass

    if not row:
        try:
            r = db.table("outreach_prospects").select("*").eq("id", prospect_id).limit(1).execute()
            if r.data:
                row = r.data[0]
                domain     = row["domain"]
                email_body = row.get("email_body") or ""
                to_email   = row.get("contact_email") or f"security@{domain}"
        except Exception:
            pass

    if not row:
        raise HTTPException(404, "Prospect not found")

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
        if r.status_code not in (200, 201):
            raise HTTPException(502, f"Resend error {r.status_code}: {r.text[:200]}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, str(e))

    now = datetime.now(timezone.utc).isoformat()
    _prospect_update(db, prospect_id,
        sr_data={"outreach_status": "sent", "sent_at": now, "sent_to": to_email},
        op_data={"status": "sent", "sent_at": now, "sent_to": to_email},
    )
    try:
        db.table("outreach_log").insert({"event": "email_sent", "domain": domain, "to": to_email, "ran_at": now}).execute()
    except Exception:
        pass
    return {"status": "sent", "to": to_email, "domain": domain}


@router.post("/prospects/{prospect_id}/unapprove")
async def unapprove_prospect(prospect_id: str, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    _prospect_update(db, prospect_id,
        sr_data={"outreach_status": "pending"},
        op_data={"status": "pending"},
    )
    return {"status": "pending"}


@router.post("/prospects/bulk-approve")
async def bulk_approve(body: BulkApprove, authorization: str = Header(None)):
    require_admin(authorization)
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    for pid in body.ids:
        _prospect_update(db, pid,
            sr_data={"outreach_status": "approved", "approved_at": now},
            op_data={"status": "approved", "approved_at": now},
        )
    return {"approved": len(body.ids)}


@router.post("/prospects/schedule")
async def schedule_prospects(body: ScheduleRequest, authorization: str = Header(None)):
    """
    Admin: mark selected prospect domains as approved and set their outreach date.
    Upserts into outreach_prospects — creates row if domain not yet scanned,
    or updates status/approved_at on existing rows.
    """
    require_admin(authorization)
    db = get_db()

    # Validate date
    try:
        from datetime import datetime as _dt
        scheduled_dt = _dt.fromisoformat(body.scheduled_for).isoformat()
    except ValueError:
        raise HTTPException(400, "Invalid date format — use YYYY-MM-DD")

    upserted = []
    for domain in body.domains:
        domain = domain.lower().strip()
        if not domain:
            continue
        # Check if row exists
        existing = db.table("outreach_prospects").select("id,status").eq("domain", domain).execute()
        if existing.data:
            db.table("outreach_prospects").update({
                "status":      "approved",
                "approved_at": scheduled_dt,
            }).eq("domain", domain).execute()
        else:
            db.table("outreach_prospects").insert({
                "domain":      domain,
                "status":      "approved",
                "approved_at": scheduled_dt,
                "scanned_at":  datetime.now(timezone.utc).isoformat(),
            }).execute()
        upserted.append(domain)

    return {"scheduled": len(upserted), "scheduled_for": body.scheduled_for, "domains": upserted}


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
    import urllib.parse
    signup_url = "https://www.swarmhawk.com/register?ref=outreach&domain=" + urllib.parse.quote(domain)
    report_url = "https://www.swarmhawk.com/app/?domain=" + urllib.parse.quote(domain)
    paragraphs = "".join(f"<p style='margin:0 0 14px 0'>{p.strip()}</p>"
                         for p in text.split("\n\n") if p.strip())
    return f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;font-size:14px;color:#222;max-width:600px;margin:0 auto;padding:0;background:#f5f5f5">
  <div style="background:#0E0D12;padding:24px 32px;border-bottom:3px solid #CBFF00">
    <strong style="font-family:monospace;font-size:18px;color:#CBFF00;letter-spacing:2px">SWARMHAWK</strong>
    <div style="font-size:11px;color:#888;margin-top:4px;font-family:monospace">Domain Security Intelligence</div>
  </div>
  <div style="background:#fff;padding:32px">
    {paragraphs}
    <div style="margin:32px 0;text-align:center">
      <a href="{signup_url}" style="display:inline-block;background:#CBFF00;color:#0E0D12;font-weight:700;font-family:monospace;padding:14px 32px;border-radius:6px;text-decoration:none;font-size:14px;letter-spacing:.5px">
        ▸ Claim Your Free Security Report
      </a>
      <div style="font-size:11px;color:#999;margin-top:8px">No credit card required · Takes 60 seconds</div>
    </div>
    <div style="background:#f9f9f9;border:1px solid #eee;border-radius:6px;padding:16px;font-size:12px;color:#666">
      <strong style="color:#333">What you get for free:</strong><br>
      Full vulnerability scan of {domain} · CVE timeline · AI risk report · NIS2 compliance check
      <br><br>
      <a href="{report_url}" style="color:#0066cc;text-decoration:none">Preview your domain report →</a>
    </div>
  </div>
  <div style="background:#f5f5f5;padding:16px 32px;font-size:11px;color:#999;text-align:center">
    This is an automated security notification from SwarmHawk.<br>
    To unsubscribe reply with "unsubscribe" · <a href="https://www.swarmhawk.com" style="color:#999">swarmhawk.com</a>
  </div>
</body></html>"""


# ── Email template endpoints ──────────────────────────────────────────────────

# Default English prompt template (variables: {domain}, {sw_list}, {cve_list}, {top_cve_id}, {top_cvss})
DEFAULT_TEMPLATE = (
    "Write a short professional cold outreach email (6-8 sentences) "
    "from SwarmHawk, a European cybersecurity intelligence company, "
    "to the webmaster or IT manager of {domain}.\n\n"
    "Findings from our passive scan:\n"
    "- Exposed software: {sw_list}\n"
    "- Live CVEs: {cve_list}\n\n"
    "Requirements:\n"
    "1. Subject line on first line as: Subject: <subject>\n"
    "2. Open with {top_cve_id} (CVSS {top_cvss}) as concrete proof\n"
    "3. One sentence plain-language risk explanation\n"
    "4. Reference NIS2 compliance briefly\n"
    "5. Offer a free full security report at swarmhawk.com\n"
    "6. Professional, direct — not alarmist\n"
    "7. Sign off: The SwarmHawk Team | swarmhawk.com\n\n"
    "Output ONLY the email. No preamble. No markdown."
)

# In-memory template cache (populated from DB on first access)
_template_cache: dict = {}


def _get_country_template(country: str) -> str:
    """Return the custom prompt template for a country, or default English."""
    if country in _template_cache:
        return _template_cache[country]
    try:
        db = get_db()
        r = db.table("outreach_templates").select("prompt").eq("country", country).execute()
        if r.data:
            _template_cache[country] = r.data[0]["prompt"]
            return _template_cache[country]
    except Exception:
        pass
    return DEFAULT_TEMPLATE


class TemplateUpdate(BaseModel):
    prompt: str
    language: str = "en"


@router.get("/templates")
async def get_templates(authorization: str = Header(None)):
    """Get all country email templates (admin only)."""
    require_admin(authorization)
    db = get_db()
    try:
        r = db.table("outreach_templates").select("*").execute()
        rows = {row["country"]: row for row in (r.data or [])}
    except Exception:
        rows = {}
    # Return defaults for countries without custom template
    result = {}
    for country in list(COUNTRY_TLDS.keys())[:20]:   # first 20 most common
        result[country] = {
            "country":  country,
            "language": rows[country]["language"] if country in rows else "en",
            "prompt":   rows[country]["prompt"]   if country in rows else DEFAULT_TEMPLATE,
            "custom":   country in rows,
        }
    return {"templates": result, "default_template": DEFAULT_TEMPLATE}


@router.put("/templates/{country}")
async def save_template(country: str, body: TemplateUpdate, authorization: str = Header(None)):
    """Save a country-specific email prompt template (admin only)."""
    require_admin(authorization)
    if country not in COUNTRY_TLDS:
        raise HTTPException(400, f"Unknown country code: {country}")
    db = get_db()
    db.table("outreach_templates").upsert({
        "country":  country,
        "language": body.language,
        "prompt":   body.prompt,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }, on_conflict="country").execute()
    _template_cache[country] = body.prompt   # update in-memory cache
    return {"status": "saved", "country": country}


@router.delete("/templates/{country}")
async def reset_template(country: str, authorization: str = Header(None)):
    """Reset a country template back to default (admin only)."""
    require_admin(authorization)
    db = get_db()
    db.table("outreach_templates").delete().eq("country", country).execute()
    _template_cache.pop(country, None)
    return {"status": "reset", "country": country, "prompt": DEFAULT_TEMPLATE}


@router.post("/templates/test")
async def test_template(body: dict, authorization: str = Header(None)):
    """Generate a test email using a given template + fake domain data (admin only)."""
    require_admin(authorization)
    prompt_tpl = body.get("prompt", DEFAULT_TEMPLATE)
    test_domain = body.get("domain", "example.com")
    filled = prompt_tpl.format(
        domain=test_domain,
        sw_list="WordPress 6.1.1",
        cve_list="CVE-2023-1234 CVSS 9.8",
        top_cve_id="CVE-2023-1234",
        top_cvss="9.8",
    )
    if not ANTHROPIC_KEY:
        return {"email": f"[No ANTHROPIC_API_KEY set]\n\nPrompt that would be sent:\n\n{filled}"}
    try:
        r = req.post(
            _anthropic_url(),
            headers=_anthropic_headers({"report_type": "outreach_email", "domain": test_domain, "_user": "system"}),
            json={"model": "claude-sonnet-4-20250514", "max_tokens": 500, "messages": [{"role": "user", "content": filled}]},
            timeout=20,
        )
        if r.status_code == 200:
            return {"email": r.json()["content"][0]["text"].strip()}
    except Exception:
        pass
    return {"email": "[Generation failed]"}


# ── APScheduler daily cron ────────────────────────────────────────────────────

def start_scheduler():
    """Call from main.py startup to enable automatic daily scans."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        scheduler = BackgroundScheduler(timezone="Europe/Prague")
        scheduler.add_job(_run_scan_job, "cron", hour=2, minute=0, id="daily_prospect_scan")
        scheduler.start()
        source = "Cloudflare Radar" if CLOUDFLARE_TOKEN else "Tranco+fallback"
        print(f"[outreach] Daily scan scheduler started — 02:00 Prague (data ready by 08:00 CET), {len(COUNTRY_TLDS)} countries × {SCAN_LIMIT} domains ({source})")
        return scheduler
    except ImportError:
        print("[outreach] APScheduler not installed — add apscheduler to requirements.txt")
        return None
