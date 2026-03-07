"""
cee_scanner.checks
==================
Passive OSINT checks — all 100% legal, no authorization required.
No active exploitation. No vulnerability scanning.
Only publicly available information.

Checks:
  1. SSL certificate — expiry, issuer, validity
  2. HTTP security headers — missing headers
  3. DNS — basic misconfiguration detection
  4. HaveIBeenPwned — domain in breach databases
  5. Shodan (optional, requires free API key)
  6. Typosquat — suspicious lookalike domains registered
"""

import ssl
import socket
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("cee_scanner.checks")

TIMEOUT = 5
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}


# ── Result dataclass ──────────────────────────────────────────────────────────

class CheckResult:
    def __init__(self, check: str, domain: str):
        self.check = check
        self.domain = domain
        self.status = "ok"        # ok | warning | critical | error
        self.title = ""
        self.detail = ""
        self.score_impact = 0     # 0-25 penalty points

    def warn(self, title: str, detail: str = "", impact: int = 5):
        self.status = "warning"
        self.title = title
        self.detail = detail
        self.score_impact = impact
        return self

    def critical(self, title: str, detail: str = "", impact: int = 15):
        self.status = "critical"
        self.title = title
        self.detail = detail
        self.score_impact = impact
        return self

    def ok(self, title: str, detail: str = ""):
        self.status = "ok"
        self.title = title
        self.detail = detail
        self.score_impact = 0
        return self

    def error(self, title: str, detail: str = ""):
        self.status = "error"
        self.title = title
        self.detail = detail
        self.score_impact = 5
        return self

    def to_dict(self) -> dict:
        d = {
            "check": self.check,
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
            "score_impact": self.score_impact,
        }
        # CVE skill attaches extra structured data
        if hasattr(self, "cves"):
            d["cves"] = self.cves
        if hasattr(self, "software"):
            d["software"] = [{"product": p, "version": v} for p, v in self.software]
        return d


# ── Individual checks ─────────────────────────────────────────────────────────

def check_ssl(domain: str) -> CheckResult:
    """Check SSL certificate validity and expiry."""
    result = CheckResult("ssl", domain)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=TIMEOUT),
            server_hostname=domain
        ) as sock:
            cert = sock.getpeercert()

        # Parse expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days

            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_name = issuer.get("organizationName", "Unknown")

            if days_left < 0:
                return result.critical(
                    "SSL certificate EXPIRED",
                    f"Expired {abs(days_left)} days ago. Issuer: {issuer_name}",
                    impact=20
                )
            elif days_left <= 7:
                return result.critical(
                    f"SSL expires in {days_left} days",
                    f"Critical — expires {expiry.strftime('%Y-%m-%d')}. Issuer: {issuer_name}",
                    impact=15
                )
            elif days_left <= 30:
                return result.warn(
                    f"SSL expires in {days_left} days",
                    f"Expires {expiry.strftime('%Y-%m-%d')}. Issuer: {issuer_name}",
                    impact=8
                )
            else:
                return result.ok(
                    f"SSL valid — {days_left} days remaining",
                    f"Expires {expiry.strftime('%Y-%m-%d')}. Issuer: {issuer_name}"
                )
    except ssl.SSLCertVerificationError as e:
        return result.critical("SSL certificate invalid", str(e)[:100], impact=20)
    except ssl.CertificateError as e:
        return result.critical("SSL certificate error", str(e)[:100], impact=15)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        return result.error("SSL check failed", str(e)[:80])
    except Exception as e:
        return result.error("SSL check error", str(e)[:80])


def check_headers(domain: str) -> CheckResult:
    """Check HTTP security headers."""
    result = CheckResult("headers", domain)
    missing = []
    warnings = []

    REQUIRED_HEADERS = [
        ("strict-transport-security", "HSTS", 8),
        ("x-content-type-options", "X-Content-Type-Options", 5),
        ("x-frame-options", "X-Frame-Options", 5),
        ("content-security-policy", "CSP", 6),
    ]

    try:
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT,
            headers=HEADERS, allow_redirects=True, verify=False
        )
        response_headers = {k.lower(): v for k, v in r.headers.items()}

        total_impact = 0
        for header_key, header_name, impact in REQUIRED_HEADERS:
            if header_key not in response_headers:
                missing.append(header_name)
                total_impact += impact

        # Check for server version disclosure
        server = response_headers.get("server", "")
        if any(c.isdigit() for c in server):
            warnings.append(f"Server version disclosed: {server}")
            total_impact += 3

        if missing:
            return result.warn(
                f"{len(missing)} security headers missing",
                f"Missing: {', '.join(missing)}",
                impact=min(total_impact, 20)
            )
        return result.ok(
            "Security headers present",
            f"HSTS, CSP, X-Frame-Options all set"
        )

    except requests.exceptions.SSLError:
        return result.critical("HTTPS not available", "Site not accessible over HTTPS", impact=15)
    except Exception as e:
        return result.error("Header check failed", str(e)[:80])


def check_dns(domain: str) -> CheckResult:
    """Check basic DNS configuration."""
    result = CheckResult("dns", domain)
    issues = []

    try:
        # Check if domain resolves
        ip = socket.gethostbyname(domain)

        # Check for common misconfigurations via TXT records
        # (using basic socket, no dnspython dependency)
        try:
            import subprocess
            # Check SPF record exists (email spoofing protection)
            spf = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=5
            )
            if spf.returncode == 0:
                if "v=spf1" not in spf.stdout:
                    issues.append("No SPF record (email spoofing risk)")
            else:
                # dig not available — skip DNS text record checks
                pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        if issues:
            return result.warn(
                f"{len(issues)} DNS issue(s) found",
                " | ".join(issues),
                impact=5 * len(issues)
            )
        return result.ok(f"DNS resolves to {ip}")

    except socket.gaierror:
        return result.critical("Domain does not resolve", "DNS lookup failed", impact=20)
    except Exception as e:
        return result.error("DNS check failed", str(e)[:80])


def check_http_redirect(domain: str) -> CheckResult:
    """Check if HTTP redirects to HTTPS."""
    result = CheckResult("https_redirect", domain)
    try:
        r = requests.get(
            f"http://{domain}", timeout=TIMEOUT,
            headers=HEADERS, allow_redirects=False, verify=False
        )
        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("location", "")
            if location.startswith("https://"):
                return result.ok("HTTP → HTTPS redirect working")
            else:
                return result.warn(
                    "HTTP redirect not to HTTPS",
                    f"Redirects to: {location[:60]}",
                    impact=8
                )
        elif r.status_code == 200:
            return result.warn(
                "HTTP served without redirect",
                "Site accessible over plain HTTP — no HTTPS enforcement",
                impact=10
            )
        else:
            return result.ok(f"HTTP returns {r.status_code}")
    except Exception as e:
        return result.error("Redirect check failed", str(e)[:80])


def check_breach(domain: str) -> CheckResult:
    """Check HaveIBeenPwned for domain breaches."""
    result = CheckResult("breach", domain)
    try:
        # HIBP v3 API — domain search (public endpoint, no key needed for domain lookup)
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": domain},
            headers={**HEADERS, "hibp-api-key": ""},
            timeout=TIMEOUT
        )

        if r.status_code == 200:
            breaches = r.json()
            if breaches:
                breach_names = [b.get("Name", "?") for b in breaches[:3]]
                total = len(breaches)
                return result.critical(
                    f"Domain in {total} breach(es)",
                    f"Found in: {', '.join(breach_names)}"
                    + (f" +{total-3} more" if total > 3 else ""),
                    impact=15
                )
            return result.ok("No known breaches found")
        elif r.status_code == 404:
            return result.ok("No known breaches found")
        elif r.status_code == 401:
            # API key required for this endpoint — skip gracefully
            return result.ok("Breach check skipped (API key required)")
        else:
            return result.error(f"Breach API returned {r.status_code}")

    except Exception as e:
        return result.error("Breach check failed", str(e)[:80])


def check_typosquat(domain: str) -> CheckResult:
    """Check for registered typosquat lookalike domains."""
    result = CheckResult("typosquat", domain)

    # Generate common typosquats
    parts = domain.split(".")
    if len(parts) < 2:
        return result.ok("Typosquat check skipped")

    name = parts[0]
    tld = ".".join(parts[1:])

    candidates = set()

    # Character substitutions
    substitutions = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}
    for i, c in enumerate(name):
        if c in substitutions:
            variant = name[:i] + substitutions[c] + name[i+1:]
            candidates.add(f"{variant}.{tld}")

    # Missing/double character
    for i in range(len(name)):
        candidates.add(f"{name[:i]+name[i+1:]}.{tld}")             # missing char
        candidates.add(f"{name[:i]+name[i]+name[i]+name[i+1:]}.{tld}")  # doubled char

    # Common TLD variations
    for alt_tld in ["com", "net", "org", "io", "eu", "co"]:
        if alt_tld != tld:
            candidates.add(f"{name}.{alt_tld}")

    # Hyphen insertion (csob → c-sob, cs-ob …)
    for i in range(1, len(name)):
        candidates.add(f"{name[:i]}-{name[i:]}.{tld}")

    # Common prefix/suffix squats
    for affix in [f"{name}-{tld.split('.')[0]}", f"{tld.split('.')[0]}-{name}",
                  f"{name}online", f"{name}secure", f"my{name}"]:
        candidates.add(f"{affix}.com")

    # Check which ones resolve (registered)
    registered = []
    for candidate in list(candidates)[:25]:   # cap at 25
        try:
            socket.gethostbyname(candidate)
            registered.append(candidate)
        except socket.gaierror:
            pass

    if len(registered) >= 3:
        return result.critical(
            f"{len(registered)} typosquat domains registered",
            f"Examples: {', '.join(registered[:3])}",
            impact=10
        )
    elif registered:
        return result.warn(
            f"{len(registered)} potential typosquat domain(s)",
            f"{', '.join(registered)}",
            impact=5
        )
    return result.ok("No obvious typosquat domains detected")


def check_response_time(domain: str) -> CheckResult:
    """Check website response time."""
    result = CheckResult("performance", domain)
    try:
        start = datetime.now(timezone.utc)
        r = requests.get(
            f"https://{domain}", timeout=15,
            headers=HEADERS, allow_redirects=True, verify=False
        )
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        if elapsed > 10:
            return result.critical(
                f"Very slow response: {elapsed:.1f}s",
                "Site taking over 10 seconds to respond",
                impact=10
            )
        elif elapsed > 5:
            return result.warn(
                f"Slow response: {elapsed:.1f}s",
                f"HTTP {r.status_code} in {elapsed:.1f}s",
                impact=5
            )
        elif r.status_code >= 500:
            return result.critical(
                f"Server error: HTTP {r.status_code}",
                f"Response in {elapsed:.1f}s",
                impact=15
            )
        elif r.status_code >= 400:
            return result.warn(
                f"Client error: HTTP {r.status_code}",
                f"Response in {elapsed:.1f}s",
                impact=8
            )
        else:
            return result.ok(
                f"Responding normally: {elapsed:.1f}s",
                f"HTTP {r.status_code}"
            )
    except requests.exceptions.Timeout:
        return result.critical("Request timed out", "No response within 15s", impact=15)
    except Exception as e:
        return result.error("Performance check failed", str(e)[:80])


# ── THREAT INTELLIGENCE CHECKS ───────────────────────────────────────────────

def check_urlhaus(domain: str) -> CheckResult:
    """
    URLhaus (abuse.ch) — real-time malware URL database.
    Checks if domain is currently hosting or distributing malware.
    Free API, no key required.
    """
    result = CheckResult("urlhaus", domain)
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            query_status = data.get("query_status", "")

            if query_status == "is_host":
                urls = data.get("urls", [])
                active = [u for u in urls if u.get("url_status") == "online"]
                tags = list({t for u in urls for t in u.get("tags") or []})[:5]
                malware_names = list({
                    u.get("threat", "") for u in urls if u.get("threat")
                })[:3]

                if active:
                    return result.critical(
                        f"ACTIVE MALWARE — {len(active)} live malicious URL(s)",
                        f"Threats: {', '.join(malware_names) or 'unknown'} | "
                        f"Tags: {', '.join(tags) or '—'}",
                        impact=25
                    )
                elif urls:
                    return result.warn(
                        f"Historical malware — {len(urls)} past URL(s) flagged",
                        f"All offline now. Threats: {', '.join(malware_names) or 'unknown'}",
                        impact=10
                    )
            elif query_status == "no_results":
                return result.ok("No malware URLs found in URLhaus")
            else:
                return result.ok(f"URLhaus: {query_status}")
        return result.error(f"URLhaus API returned {r.status_code}")
    except Exception as e:
        return result.error("URLhaus check failed", str(e)[:80])


def check_google_safebrowsing(domain: str, api_key: str = "") -> CheckResult:
    """
    Google Safe Browsing API — checks if Chrome has flagged this domain.
    Free API key from console.cloud.google.com (10,000 req/day free).
    Falls back to graceful skip if no key provided.
    """
    import os
    result = CheckResult("safebrowsing", domain)
    key = api_key or os.getenv("GOOGLE_SAFEBROWSING_KEY", "")

    if not key:
        # Try without key — limited but sometimes works
        result.ok("Safe Browsing: no API key (set GOOGLE_SAFEBROWSING_KEY)")
        return result

    try:
        payload = {
            "client": {"clientId": "cee-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"https://{domain}"},
                    {"url": f"http://{domain}"},
                ],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=payload,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = list({m.get("threatType", "UNKNOWN") for m in matches})
                return result.critical(
                    f"GOOGLE FLAGGED — {', '.join(threat_types)}",
                    f"Chrome shows security warning for this domain. "
                    f"{len(matches)} threat match(es) confirmed.",
                    impact=25
                )
            return result.ok("Google Safe Browsing: clean")
        elif r.status_code == 400:
            return result.error("Safe Browsing: invalid API key")
        else:
            return result.error(f"Safe Browsing API: HTTP {r.status_code}")
    except Exception as e:
        return result.error("Safe Browsing check failed", str(e)[:80])


def check_virustotal(domain: str, api_key: str = "") -> CheckResult:
    """
    VirusTotal — 70+ antivirus engines + threat intel aggregation.
    Free API key from virustotal.com (4 req/min, 500/day free).
    Falls back to graceful skip if no key provided.
    """
    import os
    result = CheckResult("virustotal", domain)
    key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    if not key:
        return result.ok("VirusTotal: no API key (set VIRUSTOTAL_API_KEY)")

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={**HEADERS, "x-apikey": key},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            categories = attrs.get("categories", {})
            cat_values = list(set(categories.values()))[:3]
            reputation = attrs.get("reputation", 0)

            if malicious >= 5:
                return result.critical(
                    f"VIRUSTOTAL — {malicious}/{total} engines: MALICIOUS",
                    f"Reputation: {reputation} | "
                    f"Categories: {', '.join(cat_values) or '—'}",
                    impact=25
                )
            elif malicious >= 2 or suspicious >= 5:
                return result.warn(
                    f"VirusTotal — {malicious} malicious, {suspicious} suspicious",
                    f"Reputation score: {reputation} | "
                    f"Categories: {', '.join(cat_values) or '—'}",
                    impact=12
                )
            elif malicious == 1:
                return result.warn(
                    f"VirusTotal — 1 engine flagged as malicious",
                    f"Reputation: {reputation} (possible false positive)",
                    impact=6
                )
            else:
                return result.ok(
                    f"VirusTotal: clean ({total} engines checked)",
                    f"Reputation: {reputation} | "
                    f"Categories: {', '.join(cat_values) or '—'}"
                )
        elif r.status_code == 404:
            return result.ok("VirusTotal: domain not in database yet")
        elif r.status_code == 401:
            return result.error("VirusTotal: invalid API key")
        elif r.status_code == 429:
            return result.error("VirusTotal: rate limit hit (4 req/min on free tier)")
        else:
            return result.error(f"VirusTotal API: HTTP {r.status_code}")
    except Exception as e:
        return result.error("VirusTotal check failed", str(e)[:80])


def check_spamhaus(domain: str) -> CheckResult:
    """
    Spamhaus DBL — domain block list.
    DNS-based lookup, completely free, no API key needed.
    Checks if domain is on the spam/malware/phishing block list.
    """
    result = CheckResult("spamhaus", domain)
    try:
        lookup = f"{domain}.dbl.spamhaus.org"
        try:
            answer = socket.gethostbyname(lookup)
            # Spamhaus returns specific IPs to indicate list type
            codes = {
                "127.0.1.2": ("Spammer domain", "critical", 20),
                "127.0.1.4": ("Phishing domain", "critical", 25),
                "127.0.1.5": ("Malware domain", "critical", 25),
                "127.0.1.6": ("Botnet C&C domain", "critical", 25),
                "127.0.1.102": ("Abused legit spam", "warning", 10),
                "127.0.1.103": ("Abused legit phish", "warning", 12),
                "127.0.1.104": ("Abused legit malware", "warning", 12),
            }
            if answer in codes:
                label, severity, impact = codes[answer]
                if severity == "critical":
                    return result.critical(
                        f"SPAMHAUS BLOCKLIST — {label}",
                        f"Domain is on Spamhaus DBL ({answer}). "
                        f"Mail and web traffic likely blocked globally.",
                        impact=impact
                    )
                else:
                    return result.warn(
                        f"Spamhaus DBL — {label}",
                        f"Domain flagged ({answer})",
                        impact=impact
                    )
            else:
                # Any response = listed
                return result.warn(
                    f"Spamhaus DBL listed ({answer})",
                    "Domain appears on Spamhaus block list",
                    impact=15
                )
        except socket.gaierror:
            # NXDOMAIN = not listed = clean
            return result.ok("Spamhaus DBL: not listed — clean")
    except Exception as e:
        return result.error("Spamhaus check failed", str(e)[:80])


# ── Run all checks for a domain ───────────────────────────────────────────────

def check_email_security(domain: str) -> CheckResult:
    """Check SPF, DMARC, and DKIM email authentication records."""
    result = CheckResult("email_security", domain)
    issues = []
    found = []

    try:
        import subprocess

        try:
            spf = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=5
            )
            if spf.returncode == 0 and "v=spf1" in spf.stdout:
                found.append("SPF")
            else:
                issues.append("No SPF record (email spoofing risk)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            dmarc = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=5
            )
            if dmarc.returncode == 0 and "v=DMARC1" in dmarc.stdout:
                found.append("DMARC")
                if "p=none" in dmarc.stdout:
                    issues.append("DMARC policy is 'none' (monitoring only, no enforcement)")
            else:
                issues.append("No DMARC record (emails can be spoofed)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        for selector in ["default", "google", "mail", "dkim", "k1"]:
            try:
                dkim = subprocess.run(
                    ["dig", "+short", "TXT", f"{selector}._domainkey.{domain}"],
                    capture_output=True, text=True, timeout=3
                )
                if dkim.returncode == 0 and "v=DKIM1" in dkim.stdout:
                    found.append("DKIM")
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                break

        if not issues:
            return result.ok(
                "Email security configured",
                f"Records present: {', '.join(found)}"
            )
        return result.warn(
            f"{len(issues)} email security issue(s)",
            " | ".join(issues),
            impact=min(len(issues) * 7, 15)
        )

    except Exception as e:
        return result.error("Email security check failed", str(e)[:80])


def check_whois(domain: str) -> CheckResult:
    """Check domain registration age and expiry via RDAP."""
    result = CheckResult("whois", domain)
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={**HEADERS, "Accept": "application/rdap+json"},
            timeout=8, allow_redirects=True
        )
        if r.status_code != 200:
            return result.ok("WHOIS: domain registered (RDAP unavailable)")

        data = r.json()
        events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}

        now = datetime.now(timezone.utc)
        issues = []
        details = []

        reg_date_str = events.get("registration")
        exp_date_str = events.get("expiration")

        if reg_date_str:
            try:
                reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                age_days = (now - reg_date).days
                details.append(f"Registered {reg_date.strftime('%Y-%m-%d')} ({age_days}d ago)")
                if age_days < 30:
                    issues.append(f"Very new domain — only {age_days} days old (phishing pattern)")
                elif age_days < 180:
                    issues.append(f"Relatively new domain — {age_days} days old")
            except ValueError:
                pass

        if exp_date_str:
            try:
                exp_date = datetime.fromisoformat(exp_date_str.replace("Z", "+00:00"))
                days_left = (exp_date - now).days
                details.append(f"Expires {exp_date.strftime('%Y-%m-%d')}")
                if days_left < 0:
                    issues.append("Domain registration EXPIRED")
                elif days_left < 30:
                    issues.append(f"Domain expires in {days_left} days")
            except ValueError:
                pass

        detail_str = " | ".join(details) if details else "WHOIS data retrieved"

        if not issues:
            return result.ok("Domain WHOIS looks normal", detail_str)
        if any("expired" in i.lower() or "very new" in i.lower() for i in issues):
            return result.critical(issues[0], detail_str, impact=15)
        return result.warn(issues[0], detail_str, impact=5)

    except Exception as e:
        return result.error("WHOIS check failed", str(e)[:80])


def check_cve(domain: str) -> CheckResult:
    """CVE Enrichment Skill — detects software versions and looks up real CVEs."""
    from cee_scanner.skills.cve import check_cve as _check_cve
    return _check_cve(domain)


ALL_CHECKS = [
    check_ssl,
    check_headers,
    check_dns,
    check_http_redirect,
    check_breach,
    check_typosquat,
    check_response_time,
    check_email_security,       # SPF, DMARC, DKIM
    check_whois,                # domain age and expiry via RDAP
    # ── Real-time threat intelligence ──
    check_urlhaus,              # free, no key
    check_spamhaus,             # free, no key (DNS-based)
    check_google_safebrowsing,  # free key: console.cloud.google.com
    check_virustotal,           # free key: virustotal.com
    # ── CVE Enrichment Skill ──
    check_cve,                  # free (NVD API); set NVD_API_KEY for higher rate limits
]


def scan_domain(domain: str) -> dict:
    """Run all passive checks against a single domain."""
    results = []
    for check_fn in ALL_CHECKS:
        try:
            r = check_fn(domain)
            results.append(r.to_dict())
        except Exception as e:
            logger.error(f"Check {check_fn.__name__} failed for {domain}: {e}")
            results.append(CheckResult(check_fn.__name__, domain).error(
                "Check crashed", str(e)[:80]
            ).to_dict())

    # Calculate risk score (0=best, 100=worst)
    penalty = sum(r["score_impact"] for r in results)
    risk_score = min(100, penalty)

    critical_count = sum(1 for r in results if r["status"] == "critical")
    warning_count = sum(1 for r in results if r["status"] == "warning")

    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "critical": critical_count,
        "warnings": warning_count,
        "checks": results,
    }


# Alias used by main.py backend
run_checks = scan_domain
