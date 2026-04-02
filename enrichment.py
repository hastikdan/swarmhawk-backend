"""
enrichment.py — SwarmHawk Domain Enrichment Layer
==================================================

Fast Tier 1.5 enrichment that runs after every Tier 1 passive scan.
Reuses cee_scanner's existing check functions — no duplicated logic.

Checks (all run in parallel, total ~1-2s per domain):
  - email_security  SPF / DMARC / DKIM via DNS   (free, <300ms)
  - whois           Domain age + registrar via RDAP (free, <800ms)
  - spamhaus        DNS block list                  (free, <200ms)
  - urlhaus         Malware URL database             (free, <400ms)
  - ip_intel        IP reputation + ASN + WAF detect (free, <500ms)

Results are written to dedicated columns in scan_results so they can be
queried/filtered efficiently without parsing the full checks JSON.
"""

import re, logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

ENRICH_TIMEOUT = 20   # total wall-clock seconds for all 5 parallel checks
ENRICH_WORKERS = 5    # one thread per check


# ── Orchestration ─────────────────────────────────────────────────────────────

def run_fast_enrichment(domain: str) -> dict:
    """Run 5 fast checks from cee_scanner in parallel.

    Returns a flat dict with structured enrichment columns ready to be
    written to scan_results.  Returns {} if cee_scanner is unavailable.
    """
    try:
        from cee_scanner.checks import (
            check_email_security,
            check_whois,
            check_spamhaus,
            check_urlhaus,
            check_ip_intel,
        )
    except ImportError as e:
        log.debug(f"[enrich] cee_scanner not available: {e}")
        return {}

    checks = {
        "email_security": check_email_security,
        "whois":          check_whois,
        "spamhaus":       check_spamhaus,
        "urlhaus":        check_urlhaus,
        "ip_intel":       check_ip_intel,
    }

    raw: dict = {}
    with ThreadPoolExecutor(max_workers=ENRICH_WORKERS) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in checks.items()}
        for fut in as_completed(futures, timeout=ENRICH_TIMEOUT):
            name = futures[fut]
            try:
                raw[name] = fut.result()
            except Exception as e:
                log.debug(f"[enrich] {domain} {name}: {e}")

    return _parse_enrichment(raw)


# ── Result parsing ─────────────────────────────────────────────────────────────

def _parse_enrichment(raw: dict) -> dict:
    """Convert raw CheckResult dicts into flat, structured enrichment columns."""
    result = {
        "spf_status":      "unknown",
        "dmarc_status":    "unknown",
        "dkim_status":     "unknown",
        "domain_age_days": None,
        "registrar":       None,
        "blacklisted":     False,
        "blacklist_hits":  [],
        "urlhaus_status":  "unknown",
        "ip_reputation":   "unknown",
        "waf_detected":    False,
    }

    # ── Email security (SPF / DMARC / DKIM) ──────────────────────────────────
    es = raw.get("email_security") or {}
    if isinstance(es, dict):
        status = es.get("status", "")
        detail = (es.get("detail") or "").lower()
        if status == "ok" and detail == "no_mx":
            # Domain has no MX record — email security checks are not applicable
            result["spf_status"]   = "not_applicable"
            result["dmarc_status"] = "not_applicable"
            result["dkim_status"]  = "not_applicable"
        elif status == "ok":
            result["spf_status"]   = "present"
            result["dmarc_status"] = "present"
            result["dkim_status"]  = "present"
        elif status in ("warning", "critical"):
            result["spf_status"]   = "missing" if "spf"   in detail and "missing" in detail else "present"
            result["dmarc_status"] = "missing" if "dmarc" in detail and "missing" in detail else "present"
            result["dkim_status"]  = "missing" if "dkim"  in detail and "missing" in detail else "unknown"

    # ── WHOIS / domain age ────────────────────────────────────────────────────
    wh = raw.get("whois") or {}
    if isinstance(wh, dict):
        detail = (wh.get("detail") or "")
        age_match = re.search(r'(\d+)\s*(?:days?|d)', detail, re.IGNORECASE)
        if age_match:
            result["domain_age_days"] = int(age_match.group(1))
        reg_match = re.search(r'[Rr]egistrar[:\s]+([^\n,;]+)', detail)
        if reg_match:
            result["registrar"] = reg_match.group(1).strip()[:100]

    # ── Spamhaus ──────────────────────────────────────────────────────────────
    sp = raw.get("spamhaus") or {}
    if isinstance(sp, dict) and sp.get("status") in ("critical", "warning"):
        result["blacklisted"] = True
        result["blacklist_hits"].append("spamhaus")

    # ── URLhaus ───────────────────────────────────────────────────────────────
    uh = raw.get("urlhaus") or {}
    if isinstance(uh, dict):
        result["urlhaus_status"] = uh.get("status", "unknown")
        if uh.get("status") in ("critical", "warning"):
            result["blacklisted"] = True
            if "urlhaus" not in result["blacklist_hits"]:
                result["blacklist_hits"].append("urlhaus")

    # ── IP intel ──────────────────────────────────────────────────────────────
    ip = raw.get("ip_intel") or {}
    if isinstance(ip, dict):
        result["ip_reputation"] = ip.get("status", "unknown")
        detail_lower = (ip.get("detail") or "").lower()
        if "waf" in detail_lower or "cloudflare" in detail_lower:
            result["waf_detected"] = True
        if ip.get("status") in ("critical", "warning"):
            result["blacklisted"] = True
            if "ip_intel" not in result["blacklist_hits"]:
                result["blacklist_hits"].append("ip_intel")

    return result


# ── Risk scoring ──────────────────────────────────────────────────────────────

def enrichment_risk_penalty(enrichment: dict) -> int:
    """Return extra risk score penalty/bonus from enrichment data.

    Penalties (+):
      Missing DMARC  +5   — no email spoofing protection, easy phishing target
      Missing SPF    +3   — unauthenticated email origin
      Blacklisted   +20   — Spamhaus / URLhaus / IP blocklist hit
      Age < 30 days +10   — newly registered domain, suspicious
      IP critical   +15   — actively malicious IP reputation

    Bonuses (-):
      WAF detected   -5   — infrastructure hardening
    """
    penalty = 0
    if enrichment.get("dmarc_status") == "missing":
        penalty += 5
    if enrichment.get("spf_status") == "missing":
        penalty += 3
    if enrichment.get("blacklisted"):
        penalty += 20
    age = enrichment.get("domain_age_days")
    if age is not None and age < 30:
        penalty += 10
    if enrichment.get("ip_reputation") == "critical":
        penalty += 15
    if enrichment.get("waf_detected"):
        penalty -= 5
    return penalty
