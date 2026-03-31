"""
intel_feeds.py — Real-time threat intelligence feeds for SwarmHawk
===================================================================

Modules:
  - CISA KEV   : Known Exploited Vulnerabilities catalog (free JSON feed, no key)
  - EPSS       : Exploit Prediction Scoring System (exploit probability per CVE)
  - OSV.dev    : Open-source vulnerability DB covering npm, PyPI, Go, Maven, etc.
  - Censys     : Internet-wide host scan data (CENSYS_API_ID + CENSYS_API_SECRET)
  - BGP/ASN    : Org-wide IP prefix → reverse DNS expansion (BGPView, no key)
  - Subdomain enumeration: crt.sh (free, no key) + HackerTarget (free, no key) + VirusTotal (free 500/day, VIRUSTOTAL_API_KEY)
  - Certstream : Real-time CT log streaming worker (WebSocket)
  - Nuclei     : Active vulnerability validation via nuclei CLI binary

Environment variables:
  VIRUSTOTAL_API_KEY      — optional; enables VirusTotal passive DNS subdomains (free 500/day)
  CENSYS_API_ID           — optional; enables Censys host search
  CENSYS_API_SECRET       — optional; enables Censys host search
  NUCLEI_ENABLED          — set "false" to disable nuclei even if installed
  CERTSTREAM_ENABLED      — set "false" to disable certstream worker
"""

import os
import json
import logging
import threading
import time
import subprocess
import shutil
from datetime import datetime, timezone, timedelta
from typing import Optional, Callable

import requests as req

log = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY     = os.getenv("VIRUSTOTAL_API_KEY", "")
CENSYS_API_ID          = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET      = os.getenv("CENSYS_API_SECRET", "")
NUCLEI_ENABLED         = os.getenv("NUCLEI_ENABLED", "true").lower() not in ("0", "false", "no")
CERTSTREAM_ENABLED     = os.getenv("CERTSTREAM_ENABLED", "true").lower() not in ("0", "false", "no")

_UA = {"User-Agent": "SwarmHawk-EASM/2.0 (security research; contact security@swarmhawk.com)"}


# ── CISA KEV Cache ─────────────────────────────────────────────────────────────

class KEVCache:
    """Singleton in-memory cache of the CISA Known Exploited Vulnerabilities list.

    Refreshed every 24 hours from the official CISA JSON feed.
    No API key required. ~1,200+ CVEs as of 2026.
    """

    KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    REFRESH_HRS  = 24
    _instance    = None
    _class_lock  = threading.Lock()

    def __new__(cls):
        with cls._class_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._cve_ids:     set[str]        = set()
                inst._vuln_map:    dict[str, dict] = {}
                inst._last_refresh: Optional[datetime] = None
                inst._refresh_lock = threading.Lock()
                cls._instance = inst
        return cls._instance

    def _refresh(self) -> None:
        with self._refresh_lock:
            # Double-checked locking
            if (self._last_refresh is not None and
                    datetime.now(timezone.utc) - self._last_refresh < timedelta(hours=self.REFRESH_HRS)):
                return
            try:
                r = req.get(self.KEV_URL, timeout=30, headers=_UA)
                r.raise_for_status()
                vulns = r.json().get("vulnerabilities", [])
                new_ids, new_map = set(), {}
                for v in vulns:
                    cve = (v.get("cveID") or "").upper()
                    if cve:
                        new_ids.add(cve)
                        new_map[cve] = {
                            "product":          v.get("product", ""),
                            "vendor":           v.get("vendorProject", ""),
                            "date_added":       v.get("dateAdded", ""),
                            "due_date":         v.get("dueDate", ""),
                            "short_desc":       v.get("shortDescription", ""),
                            "required_action":  v.get("requiredAction", ""),
                        }
                self._cve_ids      = new_ids
                self._vuln_map     = new_map
                self._last_refresh = datetime.now(timezone.utc)
                log.info(f"[kev] refreshed: {len(new_ids):,} known exploited CVEs loaded")
            except Exception as e:
                log.warning(f"[kev] refresh failed: {e}")

    def _ensure_fresh(self) -> None:
        if (self._last_refresh is None or
                datetime.now(timezone.utc) - self._last_refresh > timedelta(hours=self.REFRESH_HRS)):
            self._refresh()

    def is_exploited(self, cve_id: str) -> bool:
        self._ensure_fresh()
        return cve_id.upper() in self._cve_ids

    def get_vuln(self, cve_id: str) -> Optional[dict]:
        self._ensure_fresh()
        return self._vuln_map.get(cve_id.upper())

    def count(self) -> int:
        self._ensure_fresh()
        return len(self._cve_ids)

    def preload(self) -> None:
        """Force refresh on startup so first scan doesn't pay the latency."""
        self._refresh()


kev_cache = KEVCache()


# ── EPSS ───────────────────────────────────────────────────────────────────────

_epss_cache: dict[str, tuple[float, datetime]] = {}
_EPSS_TTL = timedelta(hours=24)


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Batch-fetch EPSS scores from FIRST.org API.

    Returns {CVE_ID_UPPER: probability_float 0.0–1.0}.
    Results are cached 24 h.
    """
    if not cve_ids:
        return {}
    now    = datetime.now(timezone.utc)
    result = {}
    missing: list[str] = []

    for cid in cve_ids:
        key = cid.upper()
        if key in _epss_cache:
            score, cached_at = _epss_cache[key]
            if now - cached_at < _EPSS_TTL:
                result[key] = score
                continue
        missing.append(key)

    if missing:
        for i in range(0, len(missing), 100):
            batch = missing[i:i + 100]
            try:
                params = [("cve", c) for c in batch]
                r = req.get("https://api.first.org/data/v1/epss",
                            params=params, timeout=15, headers=_UA)
                if r.status_code == 200:
                    for entry in r.json().get("data", []):
                        cid   = entry.get("cve", "").upper()
                        score = float(entry.get("epss") or 0)
                        _epss_cache[cid] = (score, now)
                        result[cid] = score
            except Exception as e:
                log.debug(f"[epss] batch fetch failed: {e}")

    return result


# ── KEV + EPSS risk boost ──────────────────────────────────────────────────────

def kev_boost_risk(result: dict) -> dict:
    """Apply KEV and EPSS intelligence to a scan result dict.

    Rules:
      - Any CVE in CISA KEV  → risk = max(current, 95), priority = CRITICAL
      - EPSS ≥ 0.7 on any CVE → risk = max(current, 90)
      - EPSS ≥ 0.5 on any CVE → risk = max(current, 80)
    Adds 'kev_cves' list and 'epss_max' float to the result for downstream use.
    """
    cves = result.get("cves") or []
    if isinstance(cves, str):
        try:
            cves = json.loads(cves)
        except Exception:
            cves = []

    cve_ids = [c.get("id") or c.get("cve_id", "") for c in cves]
    cve_ids = [c for c in cve_ids if c]

    if not cve_ids:
        return result

    epss_scores = fetch_epss_scores(cve_ids)
    kev_cves    = []
    epss_max    = 0.0

    for cve in cves:
        cid = (cve.get("id") or cve.get("cve_id", "")).upper()
        if not cid:
            continue

        if kev_cache.is_exploited(cid):
            kev_info = kev_cache.get_vuln(cid) or {}
            kev_cves.append({**cve, **kev_info, "in_kev": True})

        score = epss_scores.get(cid, 0.0)
        if score > epss_max:
            epss_max = score

    if kev_cves:
        result["kev_cves"]   = kev_cves
        result["risk_score"] = max(result.get("risk_score") or 0, 95)
        result["priority"]   = "CRITICAL"
        log.info(f"[kev] {result.get('domain')}: {len(kev_cves)} KEV CVE(s) → CRITICAL")
    elif epss_max >= 0.7:
        result["risk_score"] = max(result.get("risk_score") or 0, 90)
        result.setdefault("priority", "CRITICAL")
    elif epss_max >= 0.5:
        result["risk_score"] = max(result.get("risk_score") or 0, 80)
        if result.get("priority") not in ("CRITICAL",):
            result["priority"] = "HIGH"

    result["epss_max"] = round(epss_max, 4)
    return result


# ── OSV.dev CVE lookup ─────────────────────────────────────────────────────────

# Maps lower-case product name substrings → (osv_package_name, osv_ecosystem)
_OSV_ECOSYSTEM_MAP: list[tuple[str, str, str]] = [
    ("wordpress",      "wordpress",                             "Packagist"),
    ("drupal",         "drupal/core",                          "Packagist"),
    ("joomla",         "joomla/joomla-cms",                    "Packagist"),
    ("jquery",         "jquery",                               "npm"),
    ("bootstrap",      "bootstrap",                            "npm"),
    ("react",          "react",                                "npm"),
    ("angular",        "angular",                              "npm"),
    ("vue",            "vue",                                  "npm"),
    ("express",        "express",                              "npm"),
    ("lodash",         "lodash",                               "npm"),
    ("axios",          "axios",                                "npm"),
    ("log4j",          "org.apache.logging.log4j:log4j-core",  "Maven"),
    ("spring",         "org.springframework:spring-core",      "Maven"),
    ("struts",         "org.apache.struts:struts2-core",       "Maven"),
    ("django",         "django",                               "PyPI"),
    ("flask",          "flask",                                "PyPI"),
    ("requests",       "requests",                             "PyPI"),
    ("pillow",         "Pillow",                               "PyPI"),
    ("rails",          "rails",                                "RubyGems"),
    ("devise",         "devise",                               "RubyGems"),
    ("laravel",        "laravel/framework",                    "Packagist"),
    ("symfony",        "symfony/symfony",                      "Packagist"),
    ("opencart",       "opencart/opencart",                    "Packagist"),
    ("magento",        "magento/magento2ce",                   "Packagist"),
    ("typo3",          "typo3/cms-core",                       "Packagist"),
    ("gin",            "github.com/gin-gonic/gin",             "Go"),
    ("beego",          "github.com/beego/beego",               "Go"),
]


def osv_query_package(package: str, version: str, ecosystem: str) -> list[dict]:
    """Query OSV.dev for vulnerabilities in package@version.

    Returns [{id, cvss, title, url, source='osv'}]
    """
    try:
        r = req.post(
            "https://api.osv.dev/v1/query",
            json={"version": version,
                  "package": {"name": package, "ecosystem": ecosystem}},
            timeout=10, headers=_UA,
        )
        if r.status_code != 200:
            return []
        results = []
        for v in r.json().get("vulns", []):
            cve_id = next(
                (a for a in v.get("aliases", []) if a.startswith("CVE-")),
                v.get("id", ""),
            )
            cvss = 0.0
            for sev in v.get("severity", []):
                raw = sev.get("score", "0")
                try:
                    # Sometimes a float string, sometimes a CVSS vector
                    cvss = max(cvss, float(raw) if "." in raw or raw.isdigit() else 0.0)
                except Exception:
                    pass
            results.append({
                "id":     cve_id,
                "cvss":   cvss,
                "title":  v.get("summary", ""),
                "url":    f"https://osv.dev/vulnerability/{v.get('id', '')}",
                "source": "osv",
            })
        return results
    except Exception as e:
        log.debug(f"[osv] {package}@{version} ({ecosystem}): {e}")
        return []


def osv_enrich_cves(software: list[dict], existing_cves: list[dict]) -> list[dict]:
    """Enrich CVE list with OSV findings for all detected software packages.

    Queries OSV for each recognised software product found during scanning.
    Returns merged, deduplicated CVE list (NVD + OSV results combined).
    """
    if not software:
        return existing_cves

    existing_ids = {(c.get("id") or "").upper() for c in existing_cves}
    new_cves     = []

    for sw in software:
        product = (sw.get("product") or "").lower()
        version = (sw.get("version") or "").strip()
        if not product or not version:
            continue

        for keyword, osv_pkg, ecosystem in _OSV_ECOSYSTEM_MAP:
            if keyword in product:
                for v in osv_query_package(osv_pkg, version, ecosystem):
                    vid = (v.get("id") or "").upper()
                    if vid and vid not in existing_ids:
                        existing_ids.add(vid)
                        new_cves.append(v)
                break  # one ecosystem match per product

    if new_cves:
        log.debug(f"[osv] found {len(new_cves)} additional CVEs from OSV")

    return existing_cves + new_cves


# ── BGP / ASN Expansion ────────────────────────────────────────────────────────

def _resolve_ip(domain: str) -> Optional[str]:
    import socket
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def bgpview_asn_info(ip: str) -> Optional[dict]:
    """Return ASN metadata + IP prefixes for an IP via BGPView (free, no key).

    Returns {asn, name, country, prefixes: [str, ...]} or None.
    """
    try:
        r = req.get(f"https://api.bgpview.io/ip/{ip}", timeout=10, headers=_UA)
        if r.status_code != 200:
            return None
        prefixes = r.json().get("data", {}).get("prefixes", [])
        if not prefixes:
            return None
        asn_data = prefixes[0].get("asn", {})
        return {
            "asn":      asn_data.get("asn"),
            "name":     asn_data.get("name", ""),
            "country":  asn_data.get("country_code", ""),
            "prefixes": [p.get("prefix") for p in prefixes if p.get("prefix")],
        }
    except Exception as e:
        log.debug(f"[bgpview] failed for {ip}: {e}")
        return None


def _rdns_prefix(cidr: str, limit: int = 128) -> list[str]:
    """Reverse-DNS all hosts in a CIDR (up to limit).

    Skips prefixes wider than /20 to avoid spending minutes on huge ranges.
    """
    import ipaddress
    import socket

    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen < 20:
            return []
        found = []
        for ip in net.hosts():
            if len(found) >= limit:
                break
            try:
                host = socket.gethostbyaddr(str(ip))[0].lower().strip()
                if host and "." in host:
                    found.append(host)
            except Exception:
                pass
        return found
    except Exception as e:
        log.debug(f"[bgpview] rdns_prefix {cidr}: {e}")
        return []


def asn_expand_domain(domain: str, max_domains: int = 500) -> list[str]:
    """Discover all FQDNs in an organisation's IP space via BGP expansion.

    Flow: domain → IP → ASN → IP prefixes → reverse DNS each prefix
    Returns list of FQDNs (excluding the input domain itself).
    """
    ip = _resolve_ip(domain)
    if not ip:
        return []

    asn = bgpview_asn_info(ip)
    if not asn:
        return []

    log.info(f"[bgpview] {domain} → {ip} → ASN{asn.get('asn')} "
             f"'{asn.get('name')}' — {len(asn.get('prefixes', []))} prefixes")

    found: set[str] = set()
    per_prefix = max(32, max_domains // max(1, len(asn.get("prefixes", []))[:10]))
    for prefix in (asn.get("prefixes") or [])[:10]:
        found.update(_rdns_prefix(prefix, limit=per_prefix))
        if len(found) >= max_domains:
            break

    found.discard(domain)
    return list(found)[:max_domains]


# ── Subdomain Enumeration (free, multi-source) ────────────────────────────────

def _crtsh_subdomains(apex: str) -> set[str]:
    """crt.sh Certificate Transparency — free, no key, covers ~80%+ of subdomains."""
    found: set[str] = set()
    try:
        r = req.get(
            "https://crt.sh/",
            params={"q": f"%.{apex}", "output": "json", "deduplicate": "Y"},
            headers=_UA, timeout=30,
        )
        if r.status_code != 200:
            return found
        for entry in r.json():
            for name in (entry.get("name_value") or "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(f".{apex}") or name == apex:
                    found.add(name.lower())
    except Exception as e:
        log.debug(f"[crtsh] {apex}: {e}")
    return found


def _hackertarget_subdomains(apex: str) -> set[str]:
    """HackerTarget hostsearch API — free, no key, fast."""
    found: set[str] = set()
    try:
        r = req.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": apex},
            headers=_UA, timeout=15,
        )
        if r.status_code != 200 or "error" in r.text.lower():
            return found
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts and parts[0].endswith(f".{apex}"):
                found.add(parts[0].strip().lower())
    except Exception as e:
        log.debug(f"[hackertarget] {apex}: {e}")
    return found


def _virustotal_subdomains(apex: str) -> set[str]:
    """VirusTotal passive DNS subdomains — free tier 500 req/day with API key."""
    if not VIRUSTOTAL_API_KEY:
        return set()
    found: set[str] = set()
    try:
        r = req.get(
            f"https://www.virustotal.com/api/v3/domains/{apex}/subdomains",
            headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"},
            params={"limit": 40},
            timeout=15,
        )
        if r.status_code != 200:
            return found
        for item in r.json().get("data", []):
            sub = item.get("id", "").lower().strip()
            if sub and sub.endswith(f".{apex}"):
                found.add(sub)
    except Exception as e:
        log.debug(f"[virustotal] {apex}: {e}")
    return found


def enumerate_subdomains(domain: str) -> list[str]:
    """Enumerate subdomains using free sources: crt.sh + HackerTarget + VirusTotal.

    All three sources are free with no or minimal API key requirements:
      - crt.sh: completely free, no key, CT-log based
      - HackerTarget: free, no key, up to 10 req/day per IP
      - VirusTotal: free 500 req/day with VIRUSTOTAL_API_KEY

    Returns deduplicated list of FQDNs (excluding the apex domain itself).
    """
    parts = domain.split(".")
    apex  = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    found: set[str] = set()
    found.update(_crtsh_subdomains(apex))
    found.update(_hackertarget_subdomains(apex))
    found.update(_virustotal_subdomains(apex))
    found.discard(apex)

    result = sorted(found)
    if result:
        log.info(f"[subdomain] {apex}: {len(result)} subdomains "
                 f"(crt.sh + HackerTarget + VT)")
    return result


# Keep old name as alias for backward compat with pipeline.py callers
def securitytrails_subdomains(domain: str) -> list[str]:
    """Backward-compatible alias → now routes to free multi-source enumeration."""
    return enumerate_subdomains(domain)


# ── Censys Host Search ─────────────────────────────────────────────────────────

def censys_search_org(org_name: str, limit: int = 100) -> list[dict]:
    """Search Censys for hosts belonging to an organisation.

    Requires CENSYS_API_ID + CENSYS_API_SECRET.
    Returns [{ip, protocols, autonomous_system, services: [...]}]
    """
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return []

    try:
        r = req.post(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            json={"q": f'autonomous_system.name: "{org_name}"', "per_page": min(limit, 100)},
            headers={"Accept": "application/json"},
            timeout=20,
        )
        if r.status_code != 200:
            log.warning(f"[censys] HTTP {r.status_code}")
            return []
        hits = r.json().get("result", {}).get("hits", [])
        results = []
        for h in hits:
            results.append({
                "ip":               h.get("ip"),
                "asn":              h.get("autonomous_system", {}).get("asn"),
                "org":              h.get("autonomous_system", {}).get("name", ""),
                "country":          h.get("location", {}).get("country_code", ""),
                "open_ports":       [s.get("port") for s in h.get("services", []) if s.get("port")],
                "services":         [s.get("service_name", "") for s in h.get("services", [])],
            })
        return results
    except Exception as e:
        log.warning(f"[censys] search failed: {e}")
        return []


def censys_get_host(ip: str) -> Optional[dict]:
    """Fetch full host detail from Censys for a single IP."""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return None
    try:
        r = req.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            timeout=15,
        )
        if r.status_code != 200:
            return None
        data = r.json().get("result", {})
        return {
            "ip":         data.get("ip"),
            "asn":        data.get("autonomous_system", {}).get("asn"),
            "org":        data.get("autonomous_system", {}).get("name", ""),
            "country":    data.get("location", {}).get("country_code", ""),
            "open_ports": [s.get("port") for s in data.get("services", []) if s.get("port")],
            "services":   [{"port": s.get("port"),
                            "name": s.get("service_name", ""),
                            "banner": (s.get("banner") or "")[:200]}
                           for s in data.get("services", [])],
        }
    except Exception as e:
        log.debug(f"[censys] get_host {ip}: {e}")
        return None


# ── Certstream Worker ──────────────────────────────────────────────────────────

_certstream_running = False
_certstream_thread:  Optional[threading.Thread] = None


def start_certstream_worker(
    ingest_fn: Callable[[list[str], str], None],
    watchlist: Optional[list[str]] = None,
) -> Optional[threading.Thread]:
    """Start a background thread consuming the Certstream CT log WebSocket feed.

    ingest_fn: called with (domains: list[str], source: "certstream") per batch.
    watchlist: if provided, only domains containing one of these keywords are ingested.
               If None, every new registration is ingested (high volume — use watchlist
               in production to avoid flooding domain_queue).

    Returns thread handle or None if certstream package is not installed.
    """
    global _certstream_running, _certstream_thread

    if not CERTSTREAM_ENABLED:
        log.info("[certstream] disabled via CERTSTREAM_ENABLED env var")
        return None

    if _certstream_running:
        log.warning("[certstream] worker already running")
        return _certstream_thread

    def _worker():
        global _certstream_running
        _certstream_running = True
        log.info("[certstream] starting real-time CT log stream from certstream.calidog.io")

        pending: list[str] = []
        last_flush          = time.monotonic()
        BATCH_SIZE          = 100
        FLUSH_INTERVAL      = 30  # seconds

        while _certstream_running:
            try:
                import certstream  # pip install certstream

                def _on_cert(message, context):
                    nonlocal pending, last_flush
                    if message.get("message_type") != "certificate_update":
                        return
                    leaf        = message.get("data", {}).get("leaf_cert", {})
                    all_domains = leaf.get("all_domains", [])

                    for domain in all_domains:
                        domain = domain.lower().strip().lstrip("*.")
                        if not domain or "." not in domain or len(domain) > 253:
                            continue
                        if watchlist and not any(kw.lower() in domain for kw in watchlist):
                            continue
                        pending.append(domain)

                    now = time.monotonic()
                    if len(pending) >= BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL:
                        batch, pending = pending[:BATCH_SIZE], pending[BATCH_SIZE:]
                        if batch:
                            try:
                                ingest_fn(batch, "certstream")
                            except Exception as ie:
                                log.warning(f"[certstream] ingest error: {ie}")
                        last_flush = now

                certstream.listen_for_events(_on_cert, url="wss://certstream.calidog.io/")

            except ImportError:
                log.warning("[certstream] 'certstream' package not installed — "
                            "run: pip install certstream")
                _certstream_running = False
                return
            except Exception as e:
                log.warning(f"[certstream] stream error: {e} — reconnecting in 15 s")
                time.sleep(15)

        log.info("[certstream] worker stopped")

    _certstream_thread = threading.Thread(target=_worker, daemon=True, name="certstream")
    _certstream_thread.start()
    return _certstream_thread


def stop_certstream_worker() -> None:
    global _certstream_running
    _certstream_running = False


# ── Nuclei Active Scanner ──────────────────────────────────────────────────────

def nuclei_scan(domain: str, tags: Optional[str] = None) -> list[dict]:
    """Run nuclei active vulnerability scanner against a domain.

    Requires nuclei binary in PATH (https://github.com/projectdiscovery/nuclei).
    Returns [{template_id, severity, name, matched_at, cvss, cve_id, confirmed=True}]

    Silently returns [] if nuclei is not installed.
    """
    if not NUCLEI_ENABLED:
        return []
    if not shutil.which("nuclei"):
        log.debug("[nuclei] binary not found in PATH")
        return []

    scan_tags = tags or "cve,exposure,misconfig,default-logins"

    try:
        proc = subprocess.run(
            [
                "nuclei",
                "-target", f"https://{domain}",
                "-tags",   scan_tags,
                "-json", "-no-color", "-silent",
                "-timeout",        "5",
                "-rate-limit",     "15",
                "-retries",        "1",
                "-max-host-error", "5",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        findings = []
        for line in proc.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                f    = json.loads(line)
                info = f.get("info", {})
                clf  = info.get("classification", {})

                severity = info.get("severity", "unknown").lower()
                cvss     = 0.0
                try:
                    if clf.get("cvss-score"):
                        cvss = float(clf["cvss-score"])
                except Exception:
                    pass

                cve_id = None
                cve_list = clf.get("cve-id") or []
                if isinstance(cve_list, list) and cve_list:
                    cve_id = cve_list[0]
                elif isinstance(cve_list, str):
                    cve_id = cve_list or None

                findings.append({
                    "template_id": f.get("template-id", ""),
                    "name":        info.get("name", ""),
                    "severity":    severity,
                    "matched_at":  f.get("matched-at", ""),
                    "cvss":        cvss,
                    "cve_id":      cve_id,
                    "description": info.get("description", "")[:300],
                    "source":      "nuclei",
                    "confirmed":   True,
                })
            except Exception:
                continue

        if findings:
            log.info(f"[nuclei] {domain}: {len(findings)} confirmed finding(s)")
        return findings

    except subprocess.TimeoutExpired:
        log.debug(f"[nuclei] {domain}: timed out")
        return []
    except Exception as e:
        log.debug(f"[nuclei] {domain}: {e}")
        return []


def nuclei_enrich_result(result: dict) -> dict:
    """Validate fingerprinted vulnerabilities with nuclei and merge into result.

    Only runs for risk_score >= 60 to avoid wasting resources on low-risk domains.
    Marks matching CVEs as confirmed=True and boosts risk for high/critical findings.
    """
    if result.get("risk_score", 0) < 60:
        return result

    findings = nuclei_scan(result.get("domain", ""))
    if not findings:
        return result

    cves = result.get("cves") or []
    if isinstance(cves, str):
        try:
            cves = json.loads(cves)
        except Exception:
            cves = []

    existing_ids = {(c.get("id") or "").upper() for c in cves}

    for f in findings:
        cve_id = f.get("cve_id")
        if not cve_id:
            continue
        cid = cve_id.upper()
        if cid not in existing_ids:
            existing_ids.add(cid)
            cves.append({
                "id":        cve_id,
                "cvss":      f.get("cvss", 0),
                "title":     f.get("name", ""),
                "source":    "nuclei",
                "confirmed": True,
            })
        else:
            for c in cves:
                if (c.get("id") or "").upper() == cid:
                    c["confirmed"]      = True
                    c["nuclei_matched"] = f.get("matched_at", "")

    result["cves"]            = cves
    result["nuclei_findings"] = findings

    new_max_cvss = max((c.get("cvss") or 0 for c in cves), default=0.0)
    if new_max_cvss > (result.get("max_cvss") or 0):
        result["max_cvss"] = new_max_cvss

    critical_count = sum(1 for f in findings if f.get("severity") in ("critical", "high"))
    if critical_count > 0:
        boost = min(15, critical_count * 5)
        result["risk_score"] = max(result.get("risk_score", 0), 80 + boost)

    return result


# ── Refresh entrypoint (for cron) ──────────────────────────────────────────────

def refresh_intel_feeds() -> dict:
    """Preload/refresh all cacheable intel sources. Call once at startup and daily.

    Returns summary dict of loaded counts.
    """
    kev_cache.preload()
    return {"kev_cves": kev_cache.count()}
