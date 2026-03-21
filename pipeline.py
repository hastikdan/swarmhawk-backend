"""
pipeline.py — SwarmHawk Global Domain Security Pipeline
========================================================

Architecture:
  1. Discovery (daily 01:00 Prague)
       Cloudflare Radar — top-N domains per country, ALL ~60 countries
       Certificate Transparency logs — crt.sh, newly issued certs
       Umbrella/Tranco — top-1M filtered by TLD (weekly)
       → New domains inserted into domain_queue

  2. Tier 1 scan (daily 02:00 Prague, immediately after discovery)
       Process domain_queue: software detection + NVD CVE lookup (2 checks)
       50 parallel workers
       → Results upserted into scan_results
       → Domains with CVSS >= threshold also written to outreach_prospects (dual-write)

  3. Tier 2 enrichment (weekly, Sunday 03:00 Prague)
       Pick oldest last_scanned_at domains from scan_results
       Run full 22-check scan_domain() engine on each
       5000 domains per run, 50 parallel workers
       → Update scan_results in-place (risk_score, checks, critical, warnings)
       → Preserve outreach_status (never reset approved/sent)

Over time: scan_results grows into world's largest domain security database.
Every domain ever discovered gets weekly vulnerability tracking.
"""

import os, re, json, time, logging
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests as req

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
CLOUDFLARE_TOKEN      = os.getenv("CLOUDFLARE_API_TOKEN", "")
PIPELINE_WORKERS      = int(os.getenv("PIPELINE_WORKERS", "50"))
TIER1_BATCH_SIZE      = int(os.getenv("PIPELINE_TIER1_BATCH", "500"))
TIER2_BATCH_SIZE      = int(os.getenv("PIPELINE_TIER2_BATCH", "2000"))
RADAR_LIMIT           = int(os.getenv("PIPELINE_RADAR_LIMIT", "100"))   # per country
CT_LIMIT              = int(os.getenv("PIPELINE_CT_LIMIT", "500"))
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


def compute_unified_risk(max_cvss: float, checks: list, software: list) -> int:
    """Unified 0-100 risk score across both scan tiers.

    Tier 1 (no checks list): score from CVE + software only.
    Tier 2 (full checks): adds penalty from check results.
    """
    cve_score = min(60, int(max_cvss * 6))
    check_score = 0
    if checks:
        critical = sum(1 for c in checks if c.get("status") == "critical")
        warnings = sum(1 for c in checks if c.get("status") == "warning")
        check_score = min(20, critical * 5 + warnings * 2)
    sw_score = min(20, len(software) * 5) if software else 0
    return min(100, cve_score + check_score + sw_score)


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

    checks   = result.get("checks") or []
    software = result.get("software") or []
    cves     = result.get("cves") or []
    risk     = result.get("risk_score") or compute_unified_risk(max_cvss, checks, software)

    if max_cvss >= 9:       priority = "CRITICAL"
    elif max_cvss >= 7:     priority = "HIGH"
    elif max_cvss >= 4:     priority = "MEDIUM"
    elif max_cvss > 0:      priority = "LOW"
    else:                   priority = "INFO"

    scan_data = {
        "tld":             tld,
        "country":         country,
        "risk_score":      risk,
        "critical":        result.get("critical", 0),
        "warnings":        result.get("warnings", 0),
        "checks":          json.dumps(checks),
        "software":        json.dumps(software),
        "cves":            json.dumps(cves[:10]),
        "max_cvss":        max_cvss,
        "scan_tier":       tier,
        "source":          result.get("source", "unknown"),
        "contact_email":   result.get("contact_email") or "",
        "contact_emails":  json.dumps(result.get("contact_emails") or []),
        "priority":        priority,
        "last_scanned_at": now,
        "next_scan_at":    next_scan,
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


def ingest_domains(domains: list[str], source: str, country: Optional[str] = None, db=None):
    """Bulk-insert new domains into domain_queue.

    Skips domains already present in scan_results or domain_queue.
    Returns count of newly queued domains.
    """
    db = db or _get_db()
    if not domains:
        return 0

    # Fetch existing domains from scan_results to avoid re-queuing
    try:
        existing_sr = {
            r["domain"] for r in
            db.table("scan_results").select("domain").in_("domain", domains).execute().data or []
        }
    except Exception:
        existing_sr = set()

    _domain_re = re.compile(r'^[a-z0-9][a-z0-9\-\.]{1,253}[a-z0-9]$')
    new_domains = [
        d.lower().strip() for d in domains
        if d.lower().strip() not in existing_sr
        and _domain_re.match(d.lower().strip())
        and "." in d
    ]
    if not new_domains:
        return 0

    rows = []
    for d in new_domains:
        cc = country or infer_country(d)
        rows.append({
            "domain":   d,
            "country":  cc,
            "source":   source,
            "priority": 3 if source == "radar" else 5,
        })

    # Batch upsert — ignore conflicts (domain already queued)
    try:
        db.table("domain_queue").upsert(rows, on_conflict="domain", ignore_duplicates=True).execute()
    except Exception as e:
        log.warning(f"[pipeline] ingest_domains bulk upsert failed: {e}")
        # Fall back to individual inserts
        queued = 0
        for row in rows:
            try:
                db.table("domain_queue").insert(row).execute()
                queued += 1
            except Exception:
                pass
        return queued

    log.info(f"[pipeline] ingest_domains: queued {len(new_domains)} new domains (source={source})")
    return len(new_domains)


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
        tlds = ["com", "net", "org", "io", "ai"]  # gTLDs with highest new registration volume

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


# ── Scan workers ──────────────────────────────────────────────────────────────

def _tier1_scan_one(domain: str, country: str, source: str) -> Optional[dict]:
    """Run Tier 1 passive scan on a single domain. Returns result dict or None."""
    try:
        from outreach import scan_domain_passive
        result = scan_domain_passive(domain, country)
        if result is None:
            return None
        result["scan_tier"] = 1
        result["source"]    = source
        result["risk_score"] = compute_unified_risk(
            result.get("max_cvss", 0), [], result.get("software") or []
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

    1. Fetch top-N domains per country from Cloudflare Radar (all ~60 countries)
    2. Fetch recently issued certs from CT logs
    3. Ingest new domains into domain_queue
    """
    log.info("[discovery] starting global domain discovery")
    db = _get_db()
    total_queued = 0

    # ── Source 1: Cloudflare Radar (primary, country-aware) ─────────────────
    radar_results = fetch_radar_global(limit_per_country=RADAR_LIMIT)
    if radar_results:
        # Group by country for efficient ingest
        by_country: dict[str, list[str]] = {}
        for domain, cc in radar_results:
            by_country.setdefault(cc, []).append(domain)
        for cc, domains in by_country.items():
            total_queued += ingest_domains(domains, source="radar", country=cc, db=db)

    # ── Source 2: Certificate Transparency logs ──────────────────────────────
    ct_domains = fetch_ct_logs_recent(limit=CT_LIMIT)
    if ct_domains:
        total_queued += ingest_domains(ct_domains, source="ct_logs", db=db)

    log.info(f"[discovery] done — {total_queued} new domains queued")
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

    return {
        "queue_pending":      queue_count,
        "total_domains":      total,
        "tier2_enriched":     tier2_count,
        "high_risk_domains":  high_risk,
        "pending_outreach":   pending_outreach,
        "workers":            PIPELINE_WORKERS,
        "tier1_batch_size":   TIER1_BATCH_SIZE,
        "tier2_batch_size":   TIER2_BATCH_SIZE,
        "radar_limit":        RADAR_LIMIT,
        "radar_countries":    len(RADAR_COUNTRIES),
    }
