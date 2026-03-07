"""
cee_scanner.skills.cve
======================
CVE Enrichment Skill

Detects software and versions exposed by a domain, then queries the
NIST National Vulnerability Database (NVD) to find real CVEs with
CVSS scores.

Detection sources (all passive, no auth required):
  1. HTTP Server / X-Powered-By headers
  2. HTTP response body meta tags (WordPress, Drupal, Joomla versions)
  3. Common version-disclosure paths (/wp-login.php, /CHANGELOG.txt, etc.)
  4. Shodan banner data (if SHODAN_API_KEY set)

NVD API:
  - Free, no key required (but 5 req/30s rate limit)
  - With free API key: 50 req/30s (nvd.nist.gov/developers/request-an-api-key)
  - Returns CVSS v3 scores, severity, description, CVE IDs

Usage:
  from cee_scanner.skills.cve import check_cve
  result = check_cve("example.com")
"""

import os
import re
import time
import socket
import logging
import requests
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cee_scanner.skills.cve")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# ── Software fingerprint patterns ─────────────────────────────────────────────

# Regex patterns to extract (product, version) from HTTP headers / body
HEADER_PATTERNS = [
    # Server header
    (r"nginx/(\d+\.\d+(?:\.\d+)?)",          "nginx"),
    (r"Apache/(\d+\.\d+(?:\.\d+)?)",          "Apache HTTP Server"),
    (r"Apache-Coyote/(\d+\.\d+)",             "Apache Tomcat"),
    (r"Microsoft-IIS/(\d+\.\d+)",             "Microsoft IIS"),
    (r"LiteSpeed/(\d+\.\d+(?:\.\d+)?)",       "LiteSpeed"),
    (r"OpenSSL/(\d+\.\d+(?:\.\d+)?[a-z]?)",  "OpenSSL"),
    (r"PHP/(\d+\.\d+(?:\.\d+)?)",             "PHP"),
    # X-Powered-By header
    (r"PHP/(\d+\.\d+(?:\.\d+)?)",             "PHP"),
    (r"ASP\.NET",                              None),   # version-less, skip
    # X-Generator / X-Drupal-Cache headers
    (r"Drupal (\d+(?:\.\d+)*)",               "Drupal"),
    (r"WordPress/(\d+\.\d+(?:\.\d+)?)",       "WordPress"),
]

# Paths to probe for version disclosure
VERSION_PROBES = [
    # WordPress
    ("/wp-includes/js/jquery/jquery.min.js", [
        (r"jquery[/-](\d+\.\d+\.\d+)", "jQuery"),
    ]),
    ("/wp-login.php", [
        (r"ver=(\d+\.\d+\.\d+)", "WordPress"),
        (r'content="WordPress (\d+\.\d+)',  "WordPress"),
    ]),
    ("/wp-json/", [
        (r'"version":"(\d+\.\d+\.\d+)"', "WordPress"),
    ]),
    # Drupal
    ("/CHANGELOG.txt", [
        (r"Drupal (\d+\.\d+\.\d+),", "Drupal"),
    ]),
    ("/core/CHANGELOG.txt", [
        (r"Drupal (\d+\.\d+\.\d+),", "Drupal"),
    ]),
    # Joomla
    ("/administrator/manifests/files/joomla.xml", [
        (r"<version>(\d+\.\d+\.\d+)</version>", "Joomla"),
    ]),
    # Generic meta generator
    ("/", [
        (r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"', "WordPress"),
        (r'<meta name="generator" content="Drupal (\d+)"',                   "Drupal"),
        (r'<meta name="generator" content="Joomla! (\d+\.\d+)"',             "Joomla"),
    ]),
]

# ── NVD API query ─────────────────────────────────────────────────────────────

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map detected product names to NVD CPE keyword search terms
NVD_KEYWORDS = {
    "nginx":                "nginx",
    "Apache HTTP Server":   "apache http server",
    "Apache Tomcat":        "apache tomcat",
    "Microsoft IIS":        "microsoft iis",
    "LiteSpeed":            "litespeed web server",
    "OpenSSL":              "openssl",
    "PHP":                  "php",
    "WordPress":            "wordpress",
    "Drupal":               "drupal",
    "Joomla":               "joomla",
    "jQuery":               "jquery",
}

# CVE results cache {(product, version): cves_list} — avoids duplicate NVD calls
_cve_cache: dict = {}


def _query_nvd(product: str, version: str, api_key: str = "") -> list[dict]:
    """
    Query NVD for CVEs affecting a specific product version.
    Returns list of {id, cvss, severity, summary} dicts, sorted by CVSS desc.
    """
    cache_key = (product.lower(), version)
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    keyword = NVD_KEYWORDS.get(product, product.lower())

    # Build version-aware CPE match string where possible
    params = {
        "keywordSearch": f"{keyword} {version}",
        "keywordExactMatch": "",
        "cvssV3SeverityMin": "MEDIUM",    # skip LOW severity to reduce noise
        "resultsPerPage": 10,
    }
    hdrs = {**HEADERS, "Content-Type": "application/json"}
    if api_key:
        hdrs["apiKey"] = api_key

    try:
        # NVD rate limit: 5 req/30s without key, 50/30s with key
        time.sleep(0.7)
        r = requests.get(NVD_API, params=params, headers=hdrs, timeout=12)

        if r.status_code == 429:
            logger.warning("NVD rate limit hit — sleeping 35s")
            time.sleep(35)
            r = requests.get(NVD_API, params=params, headers=hdrs, timeout=12)

        if r.status_code != 200:
            logger.warning(f"NVD returned {r.status_code} for {product} {version}")
            _cve_cache[cache_key] = []
            return []

        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Get CVSS v3 score (fall back to v2)
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"

            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity = m.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity = m.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity = "MEDIUM" if cvss_score and cvss_score >= 4 else "LOW"

            if cvss_score is None:
                continue

            # Filter: only show CVEs that plausibly affect the detected version
            # NVD keyword search isn't version-precise — do a basic version check
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

            # Skip if version mentioned in desc and it's clearly different
            # (crude heuristic — better than nothing)
            version_major = version.split(".")[0] if version else ""
            if version_major and re.search(r'\d+\.\d+', desc):
                # If description mentions specific versions but not ours, skip
                mentioned = re.findall(r'(\d+\.\d+(?:\.\d+)?)', desc[:500])
                if mentioned and not any(v.startswith(version_major) for v in mentioned):
                    continue

            cves.append({
                "id": cve_id,
                "cvss": cvss_score,
                "severity": severity,
                "summary": desc[:200].strip(),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        # Sort by CVSS score descending, take top 5
        cves.sort(key=lambda x: x["cvss"] or 0, reverse=True)
        cves = cves[:5]

        _cve_cache[cache_key] = cves
        return cves

    except Exception as e:
        logger.warning(f"NVD query failed for {product} {version}: {e}")
        _cve_cache[cache_key] = []
        return []


# ── Software detection ────────────────────────────────────────────────────────

def _detect_from_headers(response_headers: dict) -> list[tuple[str, str]]:
    """Extract (product, version) tuples from HTTP response headers."""
    detected = []
    raw = " | ".join(f"{k}: {v}" for k, v in response_headers.items())

    for pattern, product in HEADER_PATTERNS:
        if product is None:
            continue
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else "unknown"
            if (product, version) not in detected:
                detected.append((product, version))

    return detected


def _detect_from_probes(domain: str) -> list[tuple[str, str]]:
    """Probe specific paths to extract (product, version) from response body."""
    detected = []

    for path, patterns in VERSION_PROBES:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(
                url, timeout=TIMEOUT, headers=HEADERS,
                allow_redirects=True, verify=False
            )
            if r.status_code not in (200, 206):
                continue

            content = r.text[:4000]   # only need first 4KB
            for pattern, product in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else "unknown"
                    item = (product, version)
                    if item not in detected:
                        detected.append(item)
                        logger.debug(f"Detected {product} {version} at {path}")

        except Exception:
            continue   # silently skip — path may not exist

    return detected


def _detect_from_shodan(domain: str, api_key: str) -> list[tuple[str, str]]:
    """Extract software versions from Shodan banner data."""
    if not api_key:
        return []

    detected = []
    try:
        # Resolve to IP first
        ip = socket.gethostbyname(domain)
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10,
        )
        if r.status_code != 200:
            return []

        data = r.json()

        # Extract from Shodan service banners
        for service in data.get("data", []):
            banner = service.get("data", "")
            product = service.get("product", "")
            version = service.get("version", "")

            # Shodan often gives us product+version directly
            if product and version:
                item = (product, version)
                if item not in detected:
                    detected.append(item)
                continue

            # Fall back to parsing banner text
            for pattern, prod_name in HEADER_PATTERNS:
                if prod_name is None:
                    continue
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    ver = match.group(1) if match.lastindex else "unknown"
                    item = (prod_name, ver)
                    if item not in detected:
                        detected.append(item)

    except Exception as e:
        logger.warning(f"Shodan CVE detection failed for {domain}: {e}")

    return detected


# ── Main check function ───────────────────────────────────────────────────────

def check_cve(domain: str) -> "CheckResult":
    """
    CVE Enrichment Skill — detects exposed software versions and
    matches them against the NIST NVD for real CVEs.

    Returns a CheckResult with:
    - CRITICAL if any CVE has CVSS >= 9.0 (Critical)
    - WARNING  if any CVE has CVSS >= 7.0 (High) or CVSS >= 4.0 (Medium)
    - OK       if no meaningful CVEs found
    """
    # Import here to avoid circular dependency
    from cee_scanner.checks import CheckResult

    result = CheckResult("cve", domain)

    nvd_api_key  = os.getenv("NVD_API_KEY", "")
    shodan_key   = os.getenv("SHODAN_API_KEY", "")

    # ── Step 1: Detect software ───────────────────────────────────────────────
    all_software: list[tuple[str, str]] = []

    # From HTTP headers
    try:
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT,
            headers=HEADERS, allow_redirects=True, verify=False
        )
        response_headers = {k.lower(): v for k, v in r.headers.items()}
        header_software = _detect_from_headers(response_headers)
        all_software.extend(header_software)
    except Exception as e:
        logger.debug(f"Header detection failed for {domain}: {e}")

    # From path probes
    probe_software = _detect_from_probes(domain)
    for item in probe_software:
        if item not in all_software:
            all_software.append(item)

    # From Shodan
    if shodan_key:
        shodan_software = _detect_from_shodan(domain, shodan_key)
        for item in shodan_software:
            if item not in all_software:
                all_software.append(item)

    if not all_software:
        return result.ok(
            "CVE scan: no software versions detected",
            "Server does not disclose software versions — good practice"
        )

    # ── Step 2: Query NVD for each detected software ──────────────────────────
    all_cves: list[dict] = []
    software_list: list[str] = []

    for product, version in all_software:
        software_list.append(f"{product} {version}")

        if version == "unknown":
            continue   # can't do version-specific CVE lookup

        cves = _query_nvd(product, version, nvd_api_key)
        for cve in cves:
            cve["product"] = product
            cve["version"] = version
            all_cves.append(cve)

    # Deduplicate by CVE ID
    seen_ids = set()
    unique_cves = []
    for cve in all_cves:
        if cve["id"] not in seen_ids:
            seen_ids.add(cve["id"])
            unique_cves.append(cve)

    # Sort by CVSS score
    unique_cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)

    software_str = " | ".join(software_list[:4])

    # ── Step 3: Build result ──────────────────────────────────────────────────
    if not unique_cves:
        return result.ok(
            f"CVE scan: no known CVEs found",
            f"Detected: {software_str}"
        )

    # Categorise by severity
    critical_cves = [c for c in unique_cves if (c.get("cvss") or 0) >= 9.0]
    high_cves     = [c for c in unique_cves if 7.0 <= (c.get("cvss") or 0) < 9.0]
    medium_cves   = [c for c in unique_cves if 4.0 <= (c.get("cvss") or 0) < 7.0]

    # Build detail string with top CVEs
    top = unique_cves[:3]
    cve_lines = []
    for c in top:
        cve_lines.append(
            f"{c['id']} (CVSS {c['cvss']} {c['severity']}) — "
            f"{c['product']} {c['version']}: "
            f"{c['summary'][:120]}"
        )
    detail = "\n".join(cve_lines)

    # Attach full CVE list to result for frontend rendering
    result.cves = unique_cves          # extra field — frontend can read this
    result.software = all_software     # detected software list

    if critical_cves:
        top_cvss = critical_cves[0]["cvss"]
        top_id   = critical_cves[0]["id"]
        return result.critical(
            f"{len(unique_cves)} CVE(s) — {len(critical_cves)} CRITICAL "
            f"(top: {top_id} CVSS {top_cvss})",
            detail,
            impact=25
        )
    elif high_cves:
        top_cvss = high_cves[0]["cvss"]
        top_id   = high_cves[0]["id"]
        return result.warn(
            f"{len(unique_cves)} CVE(s) — {len(high_cves)} HIGH "
            f"(top: {top_id} CVSS {top_cvss})",
            detail,
            impact=15
        )
    else:
        return result.warn(
            f"{len(unique_cves)} CVE(s) — MEDIUM severity",
            detail,
            impact=8
        )
