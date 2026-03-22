"""
pipeline.py — SwarmHawk Global Domain Security Pipeline
========================================================

Architecture:
  1. Discovery (daily 01:00 Prague)
       Cloudflare Radar — top-N domains per country, ALL ~60 countries
       Certificate Transparency logs — crt.sh, newly issued certs
       Majestic Million — top-1M by referring subnets (daily)
       → New domains inserted into domain_queue

  2. Bulk Discovery (weekly, Saturday 00:00 Prague)
       Tranco top-1M list (research-grade, deduplicated)
       Cisco Umbrella top-1M (DNS-query ranked)
       → ~2M+ new domains per week ingested into domain_queue

  3. Tier 1 scan (every 4 hours, 50 parallel workers)
       Process domain_queue: software detection + NVD CVE lookup (2 checks)
       → Results upserted into scan_results
       → Domains with CVSS >= threshold also written to outreach_prospects (dual-write)

  4. Tier 2 enrichment (weekly, Sunday 03:00 Prague)
       Pick oldest last_scanned_at domains from scan_results
       Run full 22-check scan_domain() engine on each
       2000 domains per run, 50 parallel workers
       → Update scan_results in-place (risk_score, checks, critical, warnings)
       → Preserve outreach_status (never reset approved/sent)

Over time: scan_results grows into world's largest domain security database.
Every domain ever discovered gets weekly vulnerability tracking.
"""

import os, re, json, time, logging, io, zipfile, socket
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests as req

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
CLOUDFLARE_TOKEN      = os.getenv("CLOUDFLARE_API_TOKEN", "")
PIPELINE_WORKERS      = int(os.getenv("PIPELINE_WORKERS", "50"))
TIER1_BATCH_SIZE      = int(os.getenv("PIPELINE_TIER1_BATCH", "2000"))   # 4× increase from Phase 1
TIER2_BATCH_SIZE      = int(os.getenv("PIPELINE_TIER2_BATCH", "2000"))
RADAR_LIMIT           = int(os.getenv("PIPELINE_RADAR_LIMIT", "200"))    # 2× from Phase 1
CT_LIMIT              = int(os.getenv("PIPELINE_CT_LIMIT", "1000"))
BULK_LIMIT            = int(os.getenv("PIPELINE_BULK_LIMIT", "250000"))  # domains per bulk source
CVSS_THRESHOLD        = float(os.getenv("OUTREACH_CVSS_MIN", "7.0"))
TIMEOUT               = 15
UA                    = {"User-Agent": "Mozilla/5.0 (compatible; SwarmHawk-Pipeline/1.0)"}

# Scan tier-to-reschedule interval mapping
TIER_RESCAN_DAYS = {1: 7, 2: 7}

# ── TLD → ISO-2 country map (global, 80+ countries) ──────────────────────────
# Note: COUNTRY_TLDS in outreach.py maps ISO-2 → TLD. This is the reverse.
TLD_COUNTRY: dict[str, str] = {
    # Central & Eastern Europe
    "cz": "CZ", "pl": "PL", "sk": "SK", "hu": "HU", "ro": "RO",
    "bg": "BG", "hr": "HR", "si": "SI", "rs": "RS", "ua": "UA",
    "lt": "LT", "lv": "LV", "ee": "EE", "by": "BY", "md": "MD",
    "al": "AL", "mk": "MK", "ba": "BA", "me": "ME",
    # DACH
    "de": "DE", "at": "AT", "ch": "CH",
    # Western Europe
    "fr": "FR", "es": "ES", "it": "IT", "nl": "NL", "be": "BE",
    "pt": "PT", "ie": "IE", "dk": "DK", "se": "SE", "no": "NO",
    "fi": "FI", "is": "IS", "lu": "LU", "mt": "MT",
    # UK (special case — co.uk resolves to uk)
    "uk": "GB",
    # North America
    "ca": "CA", "mx": "MX",
    # Latin America
    "br": "BR", "ar": "AR", "cl": "CL", "co": "CO",
    "pe": "PE", "ve": "VE", "uy": "UY",
    # Asia Pacific
    "au": "AU", "nz": "NZ", "jp": "JP", "kr": "KR",
    "sg": "SG", "hk": "HK", "tw": "TW", "in": "IN",
    "id": "ID", "my": "MY", "th": "TH", "ph": "PH", "vn": "VN",
    # Middle East & Africa
    "il": "IL", "ae": "AE", "sa": "SA", "za": "ZA",
    "eg": "EG", "ng": "NG", "ke": "KE", "ma": "MA", "gh": "GH",
    "tr": "TR",
    # Russia & CIS
    "ru": "RU", "kz": "KZ", "uz": "UZ", "az": "AZ", "ge": "GE",
    # Generic gTLDs — map to US as primary registry
    "com": "US", "net": "US", "org": "US", "io": "US", "ai": "US",
}

# All countries to poll from Cloudflare Radar (= all keys of outreach.COUNTRY_TLDS)
RADAR_COUNTRIES = list({v for v in TLD_COUNTRY.values()})


# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_tld(domain: str) -> str:
    """Extract the rightmost label of a domain (e.g. 'example.co.uk' -> 'uk')."""
    parts = domain.rstrip(".").lower().split(".")
    return parts[-1] if parts else ""


def infer_country(domain: str) -> str:
    """Map domain TLD to country code, default 'GLOBAL'."""
    return TLD_COUNTRY.get(extract_tld(domain), "GLOBAL")


def compute_unified_risk(max_cvss: float, checks: list, software: list,
                         enrichment: Optional[dict] = None) -> int:
    """Unified 0-100 risk score across both scan tiers.

    Tier 1 (no checks list): score from CVE + software + enrichment penalties.
    Tier 2 (full checks): adds penalty from all 22 check results.
    Enrichment penalties: missing DMARC/SPF, blacklisted, new domain, bad IP.
    """
    cve_score = min(60, int(max_cvss * 6))
    check_score = 0
    if checks:
        critical = sum(1 for c in checks if c.get("status") == "critical")
        warnings = sum(1 for c in checks if c.get("status") == "warning")
        check_score = min(20, critical * 5 + warnings * 2)
    sw_score = min(20, len(software) * 5) if software else 0
    enrich_score = 0
    if enrichment:
        try:
            from enrichment import enrichment_risk_penalty
            enrich_score = min(30, max(-10, enrichment_risk_penalty(enrichment)))
        except Exception:
            pass
    return min(100, max(0, cve_score + check_score + sw_score + enrich_score))


def _is_domain_reachable(domain: str, timeout: float = 3.0) -> bool:
    """Quick TCP reachability check on port 443 (fallback 80).

    Eliminates dead/parked domains before wasting a full scan slot.
    A 10s HTTP timeout × 600 dead domains = 100 minutes saved per batch.
    """
    for port in (443, 80):
        try:
            with socket.create_connection((domain, port), timeout=timeout):
                return True
        except (socket.timeout, socket.error, OSError):
            continue
    return False


# ── Database I/O ─────────────────────────────────────────────────────────────

def _get_db():
    from outreach import get_db
    return get_db()


def upsert_scan_result(result: dict, db=None):
    """Write unified scan result to scan_results table.

    Rules:
    - Domains with approved/sent outreach_status: only update scan fields, never reset status.
    - New domains: set outreach_status='pending' if max_cvss >= CVSS_THRESHOLD, else NULL.
    - Existing pending domains: update outreach_status if CVSS changed threshold.
    """
    db = db or _get_db()
    domain = (result.get("domain") or "").lower().strip()
    if not domain:
        return

    max_cvss = float(result.get("max_cvss") or 0)
    now      = datetime.now(timezone.utc).isoformat()
    tld      = extract_tld(domain)
    country  = result.get("country") or infer_country(domain)
    tier     = result.get("scan_tier", 1)
    next_scan = (datetime.now(timezone.utc) + timedelta(days=TIER_RESCAN_DAYS[tier])).isoformat()

    checks     = result.get("checks") or []
    software   = result.get("software") or []
    cves       = result.get("cves") or []
    enrichment = result.get("enrichment") or {}
    risk       = result.get("risk_score") or compute_unified_risk(max_cvss, checks, software, enrichment)

    if max_cvss >= 9:       priority = "CRITICAL"
    elif max_cvss >= 7:     priority = "HIGH"
    elif max_cvss >= 4:     priority = "MEDIUM"
    elif max_cvss > 0:      priority = "LOW"
    else:                   priority = "INFO"

    scan_data = {
        "tld":              tld,
        "country":          country,
        "risk_score":       risk,
        "critical":         result.get("critical", 0),
        "warnings":         result.get("warnings", 0),
        "checks":           json.dumps(checks),
        "software":         json.dumps(software),
        "cves":             json.dumps(cves[:10]),
        "max_cvss":         max_cvss,
        "scan_tier":        tier,
        "source":           result.get("source", "unknown"),
        "contact_email":    result.get("contact_email") or "",
        "contact_emails":   json.dumps(result.get("contact_emails") or []),
        "priority":         priority,
        "last_scanned_at":  now,
        "next_scan_at":     next_scan,
        # Enrichment columns (populated by Tier 1.5 fast enrichment)
        "spf_status":       enrichment.get("spf_status")      or result.get("spf_status"),
        "dmarc_status":     enrichment.get("dmarc_status")    or result.get("dmarc_status"),
        "dkim_status":      enrichment.get("dkim_status")     or result.get("dkim_status"),
        "domain_age_days":  enrichment.get("domain_age_days") or result.get("domain_age_days"),
        "registrar":        enrichment.get("registrar")       or result.get("registrar"),
        "blacklisted":      enrichment.get("blacklisted",     result.get("blacklisted", False)),
        "blacklist_hits":   json.dumps(enrichment.get("blacklist_hits") or result.get("blacklist_hits") or []),
        "urlhaus_status":   enrichment.get("urlhaus_status")  or result.get("urlhaus_status"),
        "ip_reputation":    enrichment.get("ip_reputation")   or result.get("ip_reputation"),
        "waf_detected":     enrichment.get("waf_detected",    result.get("waf_detected", False)),
    }

    try:
        existing = db.table("scan_results").select("id,outreach_status").eq("domain", domain).execute()
        if existing.data:
            row = existing.data[0]
            if row.get("outreach_status") in ("approved", "sent"):
                # Only refresh scan data — never touch outreach workflow state
                db.table("scan_results").update(scan_data).eq("id", row["id"]).execute()
                return
            new_status = "pending" if max_cvss >= CVSS_THRESHOLD else row.get("outreach_status")
            db.table("scan_results").update({
                **scan_data,
                "outreach_status": new_status,
                "email_body": result.get("email_body") or None,
            }).eq("id", row["id"]).execute()
        else:
            new_status = "pending" if max_cvss >= CVSS_THRESHOLD else None
            db.table("scan_results").insert({
                "domain":          domain,
                "outreach_status": new_status,
                "email_body":      result.get("email_body") or None,
                **scan_data,
            }).execute()
    except Exception as e:
        log.warning(f"[pipeline] upsert_scan_result failed for {domain}: {e}")


def ingest_domains(domains: list[str], source: str, country: Optional[str] = None,
                   db=None, skip_scan_check: bool = False):
    """Bulk-insert new domains into domain_queue.

    For small lists (radar, ct_logs): checks scan_results to avoid re-queuing.
    For large lists (tranco, umbrella, majestic): pass skip_scan_check=True to
    skip the expensive lookup and rely on DB-level ON CONFLICT dedup instead.
    run_tier1_batch will skip domains already in scan_results before scanning.

    Returns count of newly queued domains.
    """
    db = db or _get_db()
    if not domains:
        return 0

    _domain_re = re.compile(r'^[a-z0-9][a-z0-9\-\.]{1,253}[a-z0-9]$')

    # Normalise and deduplicate input first
    seen: set[str] = set()
    clean: list[str] = []
    for d in domains:
        d = d.lower().strip()
        if d and d not in seen and _domain_re.match(d) and "." in d:
            seen.add(d)
            clean.append(d)
    if not clean:
        return 0

    # Check scan_results in chunks of 500 to avoid massive IN clauses
    existing_sr: set[str] = set()
    if not skip_scan_check:
        for i in range(0, len(clean), 500):
            chunk = clean[i:i + 500]
            try:
                rows = db.table("scan_results").select("domain").in_("domain", chunk).execute().data or []
                existing_sr.update(r["domain"] for r in rows)
            except Exception:
                pass

    new_domains = [d for d in clean if d not in existing_sr]
    if not new_domains:
        return 0

    PRIORITY = {"radar": 3, "ct_logs": 3, "tranco": 4, "majestic": 4, "umbrella": 5}
    priority = PRIORITY.get(source, 5)

    rows = []
    for d in new_domains:
        cc = country or infer_country(d)
        rows.append({"domain": d, "country": cc, "source": source, "priority": priority})

    # Upsert in batches of 1000 — ON CONFLICT (domain) DO NOTHING
    inserted = 0
    for i in range(0, len(rows), 1000):
        batch = rows[i:i + 1000]
        try:
            db.table("domain_queue").upsert(batch, on_conflict="domain", ignore_duplicates=True).execute()
            inserted += len(batch)
        except Exception as e:
            log.warning(f"[pipeline] ingest_domains batch upsert failed (source={source}): {e}")

    log.info(f"[pipeline] ingest_domains: queued {inserted:,} domains (source={source})")
    return inserted


# ── Discovery sources ─────────────────────────────────────────────────────────

def fetch_radar_country(country_code: str, limit: int = RADAR_LIMIT) -> list[str]:
    """Fetch top-N domains for a single country from Cloudflare Radar."""
    if not CLOUDFLARE_TOKEN:
        return []
    try:
        r = req.get(
            "https://api.cloudflare.com/client/v4/radar/ranking/top",
            headers={"Authorization": f"Bearer {CLOUDFLARE_TOKEN}"},
            params={"location": country_code, "limit": limit, "format": "json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return [row["domain"] for row in r.json().get("result", {}).get("top", [])]
        log.warning(f"[radar] {country_code}: HTTP {r.status_code}")
    except Exception as e:
        log.warning(f"[radar] {country_code}: {e}")
    return []


def fetch_radar_global(limit_per_country: int = RADAR_LIMIT) -> list[tuple[str, str]]:
    """Fetch top domains across ALL countries in RADAR_COUNTRIES.

    Returns list of (domain, country_code) tuples.
    Uses 10 parallel workers to stay within Cloudflare rate limits.
    """
    if not CLOUDFLARE_TOKEN:
        log.warning("[radar] CLOUDFLARE_API_TOKEN not set — skipping global discovery")
        return []

    results: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(fetch_radar_country, cc, limit_per_country): cc for cc in RADAR_COUNTRIES}
        for fut in as_completed(futures):
            cc = futures[fut]
            try:
                domains = fut.result()
                for d in domains:
                    results.append((d, cc))
            except Exception as e:
                log.warning(f"[radar] {cc} future failed: {e}")
            time.sleep(0.05)  # gentle rate limiting

    log.info(f"[radar] global fetch: {len(results)} domains across {len(RADAR_COUNTRIES)} countries")
    return results


def fetch_ct_logs_recent(tlds: list[str] | None = None, limit: int = CT_LIMIT) -> list[str]:
    """Fetch recently issued certificates from crt.sh for given TLDs.

    Returns list of unique domain names (deduplicated, valid format only).
    Covers newly registered domains that appear in certificate transparency logs.
    """
    if tlds is None:
        # gTLDs with high registration volume + key ccTLDs
        tlds = ["com", "net", "org", "io", "ai", "de", "uk", "fr", "pl", "cz"]

    domains: set[str] = set()
    domain_re = re.compile(r'^[a-z0-9][a-z0-9\-\.]{1,253}[a-z0-9]$')

    for tld in tlds[:5]:  # cap at 5 TLDs per run to respect rate limits
        try:
            r = req.get(
                "https://crt.sh/",
                params={
                    "q":          f"%.{tld}",
                    "output":     "json",
                    "deduplicate": "Y",
                    "exclude":    "expired",
                },
                headers=UA,
                timeout=30,
            )
            if r.status_code != 200:
                continue
            for entry in r.json()[:limit]:
                raw = (entry.get("name_value") or "").lower().strip()
                # May contain wildcards or newlines — clean up
                for name in raw.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and domain_re.match(name) and "." in name:
                        domains.add(name)
        except Exception as e:
            log.warning(f"[ct_logs] tld=.{tld}: {e}")
        time.sleep(1)  # crt.sh rate limit

    result = list(domains)[:limit]
    log.info(f"[ct_logs] fetched {len(result)} new domains from CT logs")
    return result


def fetch_tranco_top1m(limit: int = BULK_LIMIT) -> list[str]:
    """Download the Tranco top-1M domain list (research-grade, de-noised).

    ~50MB zipped CSV. Returns up to `limit` domain names.
    Published weekly at https://tranco-list.eu/
    """
    try:
        r = req.get(
            "https://tranco-list.eu/top-1m.csv.zip",
            headers=UA, timeout=120,
        )
        if r.status_code != 200:
            log.warning(f"[tranco] HTTP {r.status_code}")
            return []
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            name = z.namelist()[0]
            with z.open(name) as f:
                lines = f.read().decode(errors="ignore").splitlines()
        domains = []
        for line in lines[:limit]:
            parts = line.split(",")
            if len(parts) >= 2:
                d = parts[1].strip().lower()
                if d:
                    domains.append(d)
        log.info(f"[tranco] fetched {len(domains):,} domains")
        return domains
    except Exception as e:
        log.warning(f"[tranco] failed: {e}")
        return []


def fetch_umbrella_top1m(limit: int = BULK_LIMIT) -> list[str]:
    """Download Cisco Umbrella top-1M (DNS-query ranked) domain list.

    ~30MB zipped CSV. Returns up to `limit` domain names.
    """
    try:
        r = req.get(
            "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
            headers=UA, timeout=120,
        )
        if r.status_code != 200:
            log.warning(f"[umbrella] HTTP {r.status_code}")
            return []
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            name = z.namelist()[0]
            with z.open(name) as f:
                lines = f.read().decode(errors="ignore").splitlines()
        domains = []
        for line in lines[:limit]:
            parts = line.split(",")
            if len(parts) >= 2:
                d = parts[1].strip().lower()
                if d:
                    domains.append(d)
        log.info(f"[umbrella] fetched {len(domains):,} domains")
        return domains
    except Exception as e:
        log.warning(f"[umbrella] failed: {e}")
        return []


def fetch_majestic_million(limit: int = BULK_LIMIT) -> list[str]:
    """Download Majestic Million (ranked by referring subnets) domain list.

    CSV with header. Domain is in column index 2 (GlobalRank,TldRank,Domain,...).
    Updated daily.
    """
    try:
        r = req.get(
            "https://downloads.majestic.com/majestic_million.csv",
            headers=UA, timeout=60,
        )
        if r.status_code != 200:
            log.warning(f"[majestic] HTTP {r.status_code}")
            return []
        lines = r.text.splitlines()[1:]  # skip header
        domains = []
        for line in lines[:limit]:
            parts = line.split(",")
            if len(parts) >= 3:
                d = parts[2].strip().lower()
                if d:
                    domains.append(d)
        log.info(f"[majestic] fetched {len(domains):,} domains")
        return domains
    except Exception as e:
        log.warning(f"[majestic] failed: {e}")
        return []


# ── Scan workers ──────────────────────────────────────────────────────────────

def _tier1_scan_one(domain: str, country: str, source: str) -> Optional[dict]:
    """Run Tier 1 passive scan + Tier 1.5 fast enrichment on a single domain.

    Steps:
    1. Reachability check (3s TCP) — skip dead domains immediately
    2. Passive scan: software detection + NVD CVE lookup (cached)
    3. Fast enrichment: SPF/DMARC, WHOIS age, Spamhaus, URLhaus, IP intel (parallel)
    4. Compute unified risk score including enrichment penalties
    """
    # Step 1: Dead domain pre-filter — skip 10s HTTP timeout for unreachable hosts
    if not _is_domain_reachable(domain):
        log.debug(f"[tier1] {domain}: unreachable — skipping")
        return None

    try:
        from outreach import scan_domain_passive
        result = scan_domain_passive(domain, country)
        if result is None:
            return None
        result["scan_tier"] = 1
        result["source"]    = source

        # Step 3: Fast enrichment in parallel with no extra wait
        try:
            from enrichment import run_fast_enrichment
            enrichment = run_fast_enrichment(domain)
            result["enrichment"] = enrichment
        except Exception as e:
            log.debug(f"[tier1] {domain} enrichment failed: {e}")
            enrichment = {}

        result["risk_score"] = compute_unified_risk(
            result.get("max_cvss", 0), [], result.get("software") or [], enrichment
        )
        return result
    except Exception as e:
        log.debug(f"[tier1] {domain}: {e}")
        return None


def _tier2_scan_one(domain: str, country: str) -> Optional[dict]:
    """Run Tier 2 full 22-check scan on a single domain. Returns result dict or None."""
    try:
        from cee_scanner.checks import scan_domain
        result = scan_domain(domain)
        if result is None:
            return None

        # Extract CVE/software data from check results
        cves, software = [], []
        for check in result.get("checks") or []:
            if check.get("cves"):
                cves.extend(check["cves"])
            if check.get("software"):
                software.extend(check["software"])

        max_cvss = max((c.get("cvss", 0) for c in cves), default=0.0)

        result["scan_tier"]  = 2
        result["country"]    = country
        result["max_cvss"]   = max_cvss
        result["cves"]       = cves[:10]
        result["software"]   = software
        result["risk_score"] = compute_unified_risk(
            max_cvss, result.get("checks") or [], software
        )

        if max_cvss >= 9:       result["priority"] = "CRITICAL"
        elif max_cvss >= 7:     result["priority"] = "HIGH"
        elif max_cvss >= 4:     result["priority"] = "MEDIUM"
        elif max_cvss > 0:      result["priority"] = "LOW"
        else:                   result["priority"] = "INFO"

        return result
    except Exception as e:
        log.debug(f"[tier2] {domain}: {e}")
        return None


# ── Batch processors ──────────────────────────────────────────────────────────

def run_tier1_batch(db=None, batch_size: int = TIER1_BATCH_SIZE) -> int:
    """Dequeue up to batch_size domains from domain_queue and run Tier 1 scans.

    Returns count of successfully scanned domains.
    """
    db = db or _get_db()

    try:
        rows = db.table("domain_queue")\
            .select("id,domain,country,source")\
            .order("priority", desc=False)\
            .order("queued_at", desc=False)\
            .limit(batch_size)\
            .execute()
        queue = rows.data or []
    except Exception as e:
        log.error(f"[tier1_batch] failed to fetch queue: {e}")
        return 0

    if not queue:
        log.info("[tier1_batch] queue is empty")
        return 0

    # Discard domains already in scan_results — Tier 2 will handle re-enrichment
    domain_list = [row["domain"] for row in queue]
    already_scanned: set[str] = set()
    for i in range(0, len(domain_list), 500):
        chunk = domain_list[i:i + 500]
        try:
            rows = db.table("scan_results").select("domain").in_("domain", chunk).execute().data or []
            already_scanned.update(r["domain"] for r in rows)
        except Exception:
            pass
    if already_scanned:
        stale_ids = [r["id"] for r in queue if r["domain"] in already_scanned]
        try:
            db.table("domain_queue").delete().in_("id", stale_ids).execute()
        except Exception:
            pass
        queue = [r for r in queue if r["domain"] not in already_scanned]
        log.info(f"[tier1_batch] skipped {len(stale_ids)} already-scanned domains")

    if not queue:
        log.info("[tier1_batch] all queued domains already scanned")
        return 0

    # Pre-filter dead domains with fast TCP check (3s vs 10s HTTP timeout)
    # Runs at 2× workers since socket checks are near-zero CPU
    reachable_queue = []
    dead_ids = []
    with ThreadPoolExecutor(max_workers=min(PIPELINE_WORKERS * 2, 200)) as ex:
        reach_futures = {ex.submit(_is_domain_reachable, row["domain"]): row for row in queue}
        for fut in as_completed(reach_futures):
            row = reach_futures[fut]
            try:
                if fut.result():
                    reachable_queue.append(row)
                else:
                    dead_ids.append(row["id"])
            except Exception:
                reachable_queue.append(row)  # on error assume reachable

    if dead_ids:
        try:
            db.table("domain_queue").delete().in_("id", dead_ids).execute()
        except Exception:
            pass
        log.info(f"[tier1_batch] pre-filter: {len(dead_ids)} dead domains removed, "
                 f"{len(reachable_queue)} reachable queued")
    queue = reachable_queue
    if not queue:
        log.info("[tier1_batch] no reachable domains in batch")
        return 0

    log.info(f"[tier1_batch] processing {len(queue)} domains with {PIPELINE_WORKERS} workers")
    scanned = 0
    ids_to_delete = []

    with ThreadPoolExecutor(max_workers=PIPELINE_WORKERS) as ex:
        futures = {
            ex.submit(_tier1_scan_one, row["domain"], row["country"] or infer_country(row["domain"]), row["source"] or "queue"): row
            for row in queue
        }
        for fut in as_completed(futures):
            row = futures[fut]
            ids_to_delete.append(row["id"])
            try:
                result = fut.result()
                if result:
                    upsert_scan_result(result, db)
                    # Dual-write to outreach_prospects for backward compat (Phase 1)
                    if result.get("max_cvss", 0) >= CVSS_THRESHOLD:
                        _dual_write_outreach(result, db)
                    scanned += 1
            except Exception as e:
                log.warning(f"[tier1_batch] {row['domain']}: {e}")

    # Remove processed items from queue in bulk
    if ids_to_delete:
        try:
            db.table("domain_queue").delete().in_("id", ids_to_delete).execute()
        except Exception as e:
            log.warning(f"[tier1_batch] cleanup failed: {e}")

    log.info(f"[tier1_batch] done — {scanned}/{len(queue)} scanned successfully")
    return scanned


def run_tier2_enrichment(db=None, batch_size: int = TIER2_BATCH_SIZE) -> int:
    """Run full 22-check Tier 2 scan on domains with oldest last_scanned_at.

    Picks the batch_size domains whose next_scan_at is most overdue.
    Tier 2 is the weekly deep enrichment that makes scan_results a comprehensive
    vulnerability database.
    Returns count of successfully scanned domains.
    """
    db = db or _get_db()
    now = datetime.now(timezone.utc).isoformat()

    try:
        rows = db.table("scan_results")\
            .select("id,domain,country")\
            .lte("next_scan_at", now)\
            .order("next_scan_at", desc=False)\
            .limit(batch_size)\
            .execute()
        targets = rows.data or []
    except Exception as e:
        log.error(f"[tier2_enrichment] failed to fetch targets: {e}")
        return 0

    if not targets:
        log.info("[tier2_enrichment] no domains due for enrichment")
        return 0

    log.info(f"[tier2_enrichment] enriching {len(targets)} domains with full 22-check scan")
    scanned = 0

    with ThreadPoolExecutor(max_workers=PIPELINE_WORKERS) as ex:
        futures = {
            ex.submit(_tier2_scan_one, row["domain"], row["country"] or infer_country(row["domain"])): row
            for row in targets
        }
        for fut in as_completed(futures):
            row = futures[fut]
            try:
                result = fut.result()
                if result:
                    result["source"] = "tier2_enrichment"
                    upsert_scan_result(result, db)
                    scanned += 1
            except Exception as e:
                log.warning(f"[tier2_enrichment] {row['domain']}: {e}")

    log.info(f"[tier2_enrichment] done — {scanned}/{len(targets)} domains enriched")
    return scanned


# ── Dual-write helper (Phase 1 backward compat) ───────────────────────────────

def _dual_write_outreach(result: dict, db):
    """Write qualifying scan result to outreach_prospects (backward compat for Phase 1).

    Phase 2 will remove this and migrate outreach tab to read from scan_results.
    """
    try:
        from outreach import upsert_prospect
        # upsert_prospect expects email_body; we pass empty string if none
        upsert_prospect(result, result.get("email_body") or "", db=db)
    except Exception as e:
        log.debug(f"[dual_write] {result.get('domain')}: {e}")


# ── Cron job entrypoints ──────────────────────────────────────────────────────

def run_discovery_job():
    """Daily discovery job (01:00 Prague).

    Sources: Cloudflare Radar (all countries), CT logs, Majestic Million (daily).
    Bulk sources (Tranco, Umbrella) run separately on Saturdays via run_bulk_discovery_job().
    """
    log.info("[discovery] starting daily domain discovery")
    db = _get_db()
    total_queued = 0

    # ── Source 1: Cloudflare Radar (primary, country-aware) ─────────────────
    radar_results = fetch_radar_global(limit_per_country=RADAR_LIMIT)
    if radar_results:
        by_country: dict[str, list[str]] = {}
        for domain, cc in radar_results:
            by_country.setdefault(cc, []).append(domain)
        for cc, domains in by_country.items():
            total_queued += ingest_domains(domains, source="radar", country=cc, db=db)

    # ── Source 2: Certificate Transparency logs ──────────────────────────────
    ct_domains = fetch_ct_logs_recent(limit=CT_LIMIT)
    if ct_domains:
        total_queued += ingest_domains(ct_domains, source="ct_logs", db=db)

    # ── Source 3: Majestic Million (daily updated) ───────────────────────────
    majestic_domains = fetch_majestic_million(limit=BULK_LIMIT)
    if majestic_domains:
        total_queued += ingest_domains(majestic_domains, source="majestic",
                                       db=db, skip_scan_check=True)

    log.info(f"[discovery] done — {total_queued:,} new domains queued")
    return total_queued


def run_bulk_discovery_job():
    """Weekly bulk discovery job (Saturday 00:00 Prague).

    Downloads Tranco top-1M and Cisco Umbrella top-1M.
    Together ~500k–2M net-new domains per week.
    Uses skip_scan_check=True for performance — DB-level dedup handles conflicts.
    """
    log.info("[bulk_discovery] starting weekly bulk domain discovery")
    db = _get_db()
    total_queued = 0

    # ── Source 4: Tranco top-1M (research-grade, de-noised) ─────────────────
    tranco_domains = fetch_tranco_top1m(limit=BULK_LIMIT)
    if tranco_domains:
        total_queued += ingest_domains(tranco_domains, source="tranco",
                                       db=db, skip_scan_check=True)

    # ── Source 5: Cisco Umbrella top-1M (DNS-query ranked) ──────────────────
    umbrella_domains = fetch_umbrella_top1m(limit=BULK_LIMIT)
    if umbrella_domains:
        total_queued += ingest_domains(umbrella_domains, source="umbrella",
                                       db=db, skip_scan_check=True)

    log.info(f"[bulk_discovery] done — {total_queued:,} domains queued from Tranco + Umbrella")
    return total_queued


def run_pipeline_daily():
    """Combined daily pipeline job (02:00 Prague).

    Runs after run_discovery_job has populated the queue.
    Processes domain_queue with Tier 1 scans.
    """
    log.info("[pipeline_daily] starting Tier 1 batch processing")
    db = _get_db()
    scanned = run_tier1_batch(db=db, batch_size=TIER1_BATCH_SIZE)
    log.info(f"[pipeline_daily] Tier 1 complete — {scanned} domains scanned")
    return scanned


def run_enrichment_weekly():
    """Weekly enrichment job (Sunday 03:00 Prague).

    Runs Tier 2 full 22-check scan on the oldest-scanned domains in scan_results.
    Over time this ensures every domain in the database gets a full vulnerability
    scan on a weekly cadence.
    """
    log.info("[enrichment] starting weekly Tier 2 enrichment")
    db = _get_db()
    scanned = run_tier2_enrichment(db=db, batch_size=TIER2_BATCH_SIZE)
    log.info(f"[enrichment] Tier 2 complete — {scanned} domains enriched")
    return scanned


# ── Status reporting ──────────────────────────────────────────────────────────

def get_pipeline_status(db=None) -> dict:
    """Return live pipeline statistics for the /pipeline/status endpoint."""
    db = db or _get_db()
    try:
        queue_count = db.table("domain_queue").select("id", count="exact").execute().count or 0
    except Exception:
        queue_count = -1

    try:
        total = db.table("scan_results").select("id", count="exact").execute().count or 0
    except Exception:
        total = -1

    try:
        tier2_count = db.table("scan_results").select("id", count="exact").eq("scan_tier", 2).execute().count or 0
    except Exception:
        tier2_count = -1

    try:
        high_risk = db.table("scan_results").select("id", count="exact").gte("risk_score", 60).execute().count or 0
    except Exception:
        high_risk = -1

    try:
        pending_outreach = db.table("scan_results").select("id", count="exact").eq("outreach_status", "pending").execute().count or 0
    except Exception:
        pending_outreach = -1

    try:
        by_source = {}
        for src in ("radar", "ct_logs", "majestic", "tranco", "umbrella", "outreach"):
            try:
                n = db.table("scan_results").select("id", count="exact").eq("source", src).execute().count or 0
                by_source[src] = n
            except Exception:
                pass
    except Exception:
        by_source = {}

    return {
        "queue_pending":      queue_count,
        "total_domains":      total,
        "tier2_enriched":     tier2_count,
        "high_risk_domains":  high_risk,
        "pending_outreach":   pending_outreach,
        "by_source":          by_source,
        "workers":            PIPELINE_WORKERS,
        "tier1_batch_size":   TIER1_BATCH_SIZE,
        "tier2_batch_size":   TIER2_BATCH_SIZE,
        "radar_limit":        RADAR_LIMIT,
        "radar_countries":    len(RADAR_COUNTRIES),
        "bulk_limit":         BULK_LIMIT,
    }
