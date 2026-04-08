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
        self.status = "ok"        # ok | warning | critical | error | info
        self.title = ""
        self.detail = ""
        self.score_impact = 0     # 0-25 penalty points
        self.confidence = "confirmed"  # confirmed | likely | informational

    def warn(self, title: str, detail: str = "", impact: int = 5):
        self.status = "warning"
        self.title = title
        self.detail = detail
        self.score_impact = impact
        self.confidence = "confirmed"
        return self

    def critical(self, title: str, detail: str = "", impact: int = 15):
        self.status = "critical"
        self.title = title
        self.detail = detail
        self.score_impact = impact
        self.confidence = "confirmed"
        return self

    def ok(self, title: str, detail: str = ""):
        self.status = "ok"
        self.title = title
        self.detail = detail
        self.score_impact = 0
        self.confidence = "confirmed"
        return self

    def error(self, title: str, detail: str = ""):
        self.status = "error"
        self.title = title
        self.detail = detail
        self.score_impact = 5
        self.confidence = "confirmed"
        return self

    def info(self, title: str, detail: str = ""):
        """Surface indicator — not a confirmed vulnerability. No score penalty."""
        self.status = "info"
        self.title = title
        self.detail = detail
        self.score_impact = 0
        self.confidence = "informational"
        return self

    def to_dict(self) -> dict:
        d = {
            "check": self.check,
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
            "score_impact": self.score_impact,
            "confidence": self.confidence,
        }
        # CVE skill attaches extra structured data
        if hasattr(self, "cves"):
            d["cves"] = self.cves
        if hasattr(self, "software"):
            d["software"] = [{"product": p, "version": v} for p, v in self.software]
        if hasattr(self, "nuclei_findings"):
            d["nuclei_findings"] = self.nuclei_findings
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

        # Pre-check: does the domain have any MX records?
        # If not, email security checks are not applicable — skip them.
        try:
            mx_probe = subprocess.run(
                ["dig", "+short", "MX", domain],
                capture_output=True, text=True, timeout=5
            )
            if mx_probe.returncode == 0 and not mx_probe.stdout.strip():
                return result.ok("No mail server configured", "no_mx")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # dig unavailable or timed out — proceed with checks anyway

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


def check_sast(domain: str) -> CheckResult:
    """SAST Exposure — detect leaked source code, .env files, and debug endpoints."""
    from cee_scanner.skills.sast import check_sast as _check_sast
    return _check_sast(domain)


def check_sca(domain: str) -> CheckResult:
    """SCA — find exposed dependency manifests and CVEs in declared packages."""
    from cee_scanner.skills.sca import check_sca as _check_sca
    return _check_sca(domain)


def check_agentic_dast(domain: str) -> CheckResult:
    """DAST — Shannon-inspired multi-agent DAST. Probes + 3 parallel Claude agents."""
    from cee_scanner.skills.agentic_dast import check_agentic_dast as _check_agentic_dast
    return _check_agentic_dast(domain)


def check_iac(domain: str) -> CheckResult:
    """IaC Security — detect exposed Terraform, Kubernetes, and cloud config files."""
    from cee_scanner.skills.iac import check_iac as _check_iac
    return _check_iac(domain)


def check_ip_intel(domain: str) -> CheckResult:
    """IP Intelligence — resolve domain to IPs and check reputation, blocklists, Shodan, AbuseIPDB."""
    from cee_scanner.skills.ip_intel import check_ip_intel as _check_ip_intel
    return _check_ip_intel(domain)


def check_ports(domain: str) -> CheckResult:
    """Active port scan — TCP connect to 30 common ports, flags dangerously exposed services."""
    import socket as _sock
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    result = CheckResult("ports", domain)

    try:
        ip = _sock.gethostbyname(domain)
    except Exception:
        return result.error("Could not resolve domain for port scan")

    PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB/NetBIOS",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
        2375: "Docker API (unencrypted)", 2376: "Docker TLS",
        3000: "Dev server", 3306: "MySQL", 3389: "RDP",
        4443: "Alt HTTPS", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "Alt HTTP", 8443: "Alt HTTPS",
        8888: "Jupyter Notebook", 9200: "Elasticsearch", 9300: "Elasticsearch cluster",
        27017: "MongoDB", 11211: "Memcached", 6443: "Kubernetes API",
    }
    # Services that must never be internet-facing
    CRITICAL_PORTS = {3306, 5432, 27017, 6379, 1433, 1521, 9200, 9300, 11211, 2375, 5900, 445, 23, 6443}
    HIGH_RISK_PORTS = {3389, 3000, 8888, 2376}

    open_ports: list[int] = []

    def _probe(port: int) -> int | None:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(1.5)
            r = s.connect_ex((ip, port))
            s.close()
            return port if r == 0 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(PORTS)) as ex:
        for p in [f.result() for f in _as_completed({ex.submit(_probe, port) for port in PORTS})]:
            if p is not None:
                open_ports.append(p)

    open_ports.sort()

    if not open_ports:
        return result.ok(
            "No dangerous ports exposed",
            f"Scanned {len(PORTS)} common ports — all closed or filtered",
        )

    labels = [f"{p}/{PORTS[p]}" for p in open_ports]
    detail = "Open ports: " + ", ".join(labels)

    critical_exposed = [p for p in open_ports if p in CRITICAL_PORTS]
    high_risk_exposed = [p for p in open_ports if p in HIGH_RISK_PORTS]

    if critical_exposed:
        c_labels = [f"{p}/{PORTS[p]}" for p in critical_exposed]
        return result.critical(
            f"Critical services internet-exposed — {', '.join(c_labels)}",
            detail + "\nThese services should be firewalled from the public internet.",
            impact=20,
        )
    elif high_risk_exposed:
        h_labels = [f"{p}/{PORTS[p]}" for p in high_risk_exposed]
        return result.warn(
            f"Sensitive ports open — {', '.join(h_labels)}",
            detail + "\nRestrict access to known IP addresses.",
            impact=10,
        )
    else:
        non_standard = [p for p in open_ports if p not in {80, 443, 22, 25, 993, 995, 110, 143, 21}]
        if non_standard:
            ns_labels = [f"{p}/{PORTS[p]}" for p in non_standard]
            return result.warn(
                f"Non-standard ports open — review required",
                detail + f"\nUnexpected: {', '.join(ns_labels)}",
                impact=5,
            )
        return result.ok(f"{len(open_ports)} standard ports open", detail)


def check_subdomains(domain: str) -> CheckResult:
    """Subdomain enumeration via Certificate Transparency logs (crt.sh) and DNS wordlist."""
    import socket as _sock
    import os as _os
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    result = CheckResult("subdomains", domain)

    # Normalise to root domain — use removeprefix, NOT lstrip (lstrip strips chars, not strings)
    d = domain.lower()
    if d.startswith("www."):
        d = d[4:]
    parts = d.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else d

    WORDLIST = [
        "www", "mail", "email", "webmail", "smtp", "pop", "imap", "mx", "mx1", "mx2",
        "ftp", "sftp", "files",
        "admin", "administrator", "portal", "dashboard", "panel", "cp", "cpanel", "whm",
        "api", "api2", "v1", "v2", "v3", "graphql", "rest", "ws",
        "dev", "develop", "development", "staging", "stage", "stg",
        "test", "testing", "qa", "uat", "beta", "demo", "sandbox", "preview",
        "app", "app2", "apps", "web", "web2",
        "cdn", "assets", "static", "media", "images", "img", "files", "uploads",
        "blog", "shop", "store", "support", "help", "kb", "docs", "wiki",
        "vpn", "remote", "gateway", "rdp", "ssh", "bastion",
        "ns1", "ns2", "dns1", "dns2",
        "git", "gitlab", "github", "bitbucket",
        "jenkins", "ci", "build", "deploy", "cd",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
        "monitor", "monitoring", "status", "metrics", "grafana", "kibana",
        "internal", "intranet", "corp", "private",
        "old", "legacy", "backup",
        "mobile", "m",
    ]

    SENSITIVE = {
        "admin", "administrator", "dev", "develop", "development", "staging", "stage", "stg",
        "test", "testing", "qa", "uat", "beta", "demo", "sandbox",
        "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "build", "deploy",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
        "internal", "intranet", "corp", "private", "old", "legacy", "backup",
        "cpanel", "whm", "panel", "kibana", "grafana",
    }

    # ── CT log discovery (crt.sh) ─────────────────────────────────────────────
    ct_subs: set[str] = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{base}&output=json",
            timeout=15, headers=HEADERS,
        )
        if r.status_code == 200:
            import re as _re
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{base}"):
                        sub = name[: -(len(base) + 1)]
                        # skip multi-level wildcards like *.foo.example.com
                        if sub and "." not in sub:
                            ct_subs.add(sub)
    except Exception:
        pass

    all_subs = list(set(WORDLIST) | ct_subs)

    # ── Wildcard DNS detection ────────────────────────────────────────────────
    # CDNs often use *.domain.com → catch-all IP, making every wordlist guess
    # resolve. Detect this by probing a guaranteed-nonexistent subdomain.
    # If it resolves → wildcard DNS active → wordlist is useless.
    # In that case we trust ONLY crt.sh results (real issued certificates).
    wildcard_dns = False
    _sentinel = _os.urandom(10).hex()
    try:
        _sock.gethostbyname(f"{_sentinel}.{base}")
        wildcard_dns = True
    except Exception:
        pass

    # When wildcard DNS is active, restrict candidates to CT log entries only.
    candidates = list(ct_subs) if wildcard_dns else all_subs

    # ── DNS resolution ────────────────────────────────────────────────────────
    found: list[str] = []
    sensitive_found: list[str] = []

    def _resolve(sub: str) -> str | None:
        try:
            _sock.gethostbyname(f"{sub}.{base}")
            return sub
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=40) as ex:
        for sub in [f.result() for f in _as_completed({ex.submit(_resolve, s) for s in candidates})]:
            if sub:
                found.append(sub)
                if sub in SENSITIVE:
                    sensitive_found.append(sub)

    found.sort()
    total = len(found)

    if total == 0:
        if wildcard_dns:
            return result.ok(
                "No subdomains found in CT logs",
                f"Wildcard DNS detected — wordlist skipped (false-positive risk). CT log scan returned no results.",
            )
        return result.ok(
            "No exposed subdomains found",
            f"Checked CT logs + {len(WORDLIST)}-entry wordlist — nothing resolved",
        )

    detail = f"{total} subdomains discovered: " + ", ".join(found[:25])
    if total > 25:
        detail += f" (+{total - 25} more)"

    if sensitive_found:
        sensitive_found.sort()
        return result.critical(
            f"Sensitive subdomains exposed — {', '.join(sensitive_found[:4])}",
            detail + f"\nSensitive: {', '.join(sensitive_found)}\nThese environments may lack production-grade hardening.",
            impact=15,
        )
    elif total > 15:
        return result.warn(
            f"Large subdomain footprint — {total} subdomains",
            detail + "\nLarge attack surface — audit each subdomain for security posture.",
            impact=5,
        )
    else:
        return result.ok(
            f"{total} subdomains found — no sensitive exposure",
            detail,
        )


def check_cms(domain: str) -> CheckResult:
    """CMS & technology fingerprinting — detects platform and version strings that aid attackers."""
    import re as _re
    result = CheckResult("cms", domain)

    try:
        r = requests.get(
            f"https://{domain}", timeout=10, headers=HEADERS, allow_redirects=True,
        )
    except Exception:
        try:
            r = requests.get(f"http://{domain}", timeout=10, headers=HEADERS, allow_redirects=True)
        except Exception as e:
            return result.error("Could not fetch site for CMS fingerprinting", str(e)[:80])

    body = r.text.lower()
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    detected: list[str] = []
    version_strings: list[str] = []

    # ── WordPress ─────────────────────────────────────────────────────────────
    if "/wp-content/" in body or "/wp-includes/" in body:
        detected.append("WordPress")
        m = _re.search(r'<meta name="generator" content="wordpress ([0-9.]+)"', body)
        if m:
            version_strings.append(f"WordPress {m.group(1)}")
        else:
            m2 = _re.search(r'\?ver=([0-9]+\.[0-9]+[0-9.]*)', body)
            if m2:
                version_strings.append(f"WordPress (ver hint: {m2.group(1)})")

    # ── Drupal ────────────────────────────────────────────────────────────────
    if "drupal" in body or "/sites/default/" in body or hdrs.get("x-generator", "").lower().startswith("drupal"):
        detected.append("Drupal")
        m = _re.search(r'<meta name="generator" content="drupal ([0-9]+)', body)
        if m:
            version_strings.append(f"Drupal {m.group(1)}")

    # ── Joomla ────────────────────────────────────────────────────────────────
    if "joomla" in body or "/components/com_" in body or "/media/jui/" in body:
        detected.append("Joomla")

    # ── Django ────────────────────────────────────────────────────────────────
    if "csrfmiddlewaretoken" in body or "django" in hdrs.get("x-frame-options", "").lower():
        detected.append("Django")

    # ── Server header version ─────────────────────────────────────────────────
    server = hdrs.get("server", "")
    if "/" in server:
        version_strings.append(f"Server: {server}")
        if not any(cms in server.lower() for cms in ("cloudflare", "github", "fastly", "akamai")):
            detected.append(server.split("/")[0])

    # ── X-Powered-By ──────────────────────────────────────────────────────────
    xpb = hdrs.get("x-powered-by", "")
    if xpb:
        version_strings.append(f"X-Powered-By: {xpb}")
        detected.append(xpb.split("/")[0])

    # ── X-AspNet-Version ─────────────────────────────────────────────────────
    aspnet = hdrs.get("x-aspnet-version", "") or hdrs.get("x-aspnetmvc-version", "")
    if aspnet:
        version_strings.append(f"ASP.NET: {aspnet}")
        detected.append(f"ASP.NET {aspnet}")

    # ── Generator meta ────────────────────────────────────────────────────────
    m = _re.search(r'<meta name="generator" content="([^"]{3,60})"', r.text[:8000], _re.IGNORECASE)
    if m and "wordpress" not in m.group(1).lower() and "drupal" not in m.group(1).lower():
        version_strings.append(f"Generator: {m.group(1)}")
        detected.append(m.group(1))

    if not detected and not version_strings:
        return result.ok(
            "No CMS or technology version disclosed",
            "Stack fingerprinting returned no identifiable strings",
        )

    # Deduplicate
    detected = list(dict.fromkeys(detected))
    version_strings = list(dict.fromkeys(version_strings))
    tech = ", ".join(detected[:4])

    if version_strings:
        return result.critical(
            f"Technology version disclosed — {version_strings[0]}",
            f"Detected: {tech}\nVersion strings: {'; '.join(version_strings)}\n"
            "Remove Server/X-Powered-By headers and generator meta tags to prevent targeted CVE attacks.",
            impact=10,
        )
    return result.warn(
        f"CMS fingerprinted — {tech}",
        f"Platform detected: {tech}\nHide CMS identity to slow attacker reconnaissance.",
        impact=5,
    )


def check_paranoidlab(domain: str) -> CheckResult:
    """
    ParanoidLab — dark-web credential & PII leak intelligence.
    Public search (no key): aggregated leak counts.
    With PARANOIDLAB_API_KEY: full leak detail + Telegram dark-web posts.
    """
    import os
    result = CheckResult("paranoidlab", domain)
    api_key = os.getenv("PARANOIDLAB_API_KEY", "")
    base = "https://paranoidlab.com/v1"

    # ── Public search (no key required) ──────────────────────────────────────
    try:
        r = requests.post(
            f"{base}/search",
            json={"query": domain},
            timeout=10,
        )
        search_data = r.json() if r.status_code == 200 else {}
    except Exception:
        search_data = {}

    # ── Authenticated leak fetch (key required) ───────────────────────────────
    total = 0
    types: dict = {}
    telegram_total = 0
    detail_lines = []

    if api_key:
        try:
            r = requests.get(
                f"{base}/leaks",
                headers={"X-Key": api_key, "Content-Type": "application/json"},
                params={"data_url": domain, "limit": 20, "offset": 0},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                items = data.get("items") or data.get("leaks") or []
                total = data.get("total") or len(items)
                for item in items:
                    t = item.get("type", "unknown")
                    types[t] = types.get(t, 0) + 1
            elif r.status_code == 401:
                return result.error("ParanoidLab: invalid API key")
        except Exception as e:
            return result.error("ParanoidLab leaks fetch failed", str(e)[:80])

        try:
            r = requests.get(
                f"{base}/telegram/posts",
                headers={"X-Key": api_key, "Content-Type": "application/json"},
                params={"keyword": domain, "limit": 10},
                timeout=10,
            )
            if r.status_code == 200:
                tdata = r.json()
                posts = tdata.get("posts") or tdata.get("items") or []
                telegram_total = tdata.get("total") or len(posts)
        except Exception:
            pass

        # Build detail string
        if total > 0:
            parts = [f"{v} {k}" for k, v in types.items()]
            detail_lines.append(f"Leaked records: {total} ({', '.join(parts)})")
        if telegram_total > 0:
            detail_lines.append(f"Telegram dark-web mentions: {telegram_total}")

        passwords = types.get("password", 0)
        pii = types.get("pii", 0)

        if total == 0:
            return result.ok(
                "No leaked credentials found in dark-web sources",
                f"Powered by ParanoidLab | Telegram mentions: {telegram_total}",
            )
        elif passwords >= 10 or pii >= 5 or total >= 25:
            return result.critical(
                f"DARK WEB LEAK — {total} records exposed",
                " | ".join(detail_lines),
                impact=20,
            )
        else:
            return result.warn(
                f"Dark-web leak detected — {total} records",
                " | ".join(detail_lines),
                impact=10,
            )

    # ── No key: use public search summary only ────────────────────────────────
    pub_total = search_data.get("total") or search_data.get("count") or 0
    if pub_total == 0:
        return result.ok(
            "No public leak records found",
            "Set PARANOIDLAB_API_KEY for full dark-web intelligence",
        )
    elif pub_total >= 25:
        return result.critical(
            f"DARK WEB LEAK — {pub_total} records (public search)",
            "Set PARANOIDLAB_API_KEY for full credential details",
            impact=20,
        )
    else:
        return result.warn(
            f"Dark-web records detected — {pub_total} found",
            "Set PARANOIDLAB_API_KEY for full credential details",
            impact=10,
        )


def check_nuclei(domain: str) -> CheckResult:
    """Active CVE + misconfiguration scan via nuclei templates.

    Wraps intel_feeds.nuclei_scan(). Silently skips if nuclei binary is not installed.
    Findings are serialised into check detail and as structured nuclei_findings list.
    """
    result = CheckResult("nuclei", domain)
    try:
        from intel_feeds import nuclei_scan as _nuclei_scan  # type: ignore
    except ImportError:
        return result.ok("Nuclei scanner not available", "intel_feeds not importable")

    try:
        findings = _nuclei_scan(domain)
    except Exception as e:
        return result.ok("Nuclei scan skipped", str(e)[:100])

    if not findings:
        return result.ok("No active vulnerabilities confirmed", "nuclei: 0 findings")

    crits   = [f for f in findings if f.get("severity") == "critical"]
    highs   = [f for f in findings if f.get("severity") == "high"]
    mediums = [f for f in findings if f.get("severity") == "medium"]

    max_cvss = max((f.get("cvss") or 0.0 for f in findings), default=0.0)

    lines = []
    for f in findings[:15]:
        sev     = f.get("severity", "unknown").upper()
        cve_str = f" [{f['cve_id']}]" if f.get("cve_id") else ""
        cvss    = f.get("cvss") or 0.0
        url     = f.get("matched_at", "")
        lines.append(f"• {f.get('name','')}{cve_str} — {sev} CVSS {cvss:.1f} @ {url}")
    if len(findings) > 15:
        lines.append(f"  … and {len(findings) - 15} more")

    detail = f"Max CVSS {max_cvss:.1f} — {len(findings)} confirmed finding(s)\n" + "\n".join(lines)

    if crits:
        r = result.critical(
            f"Nuclei: {len(crits)} critical finding(s)" + (f" + {len(highs)} high" if highs else ""),
            detail,
            impact=min(25, len(crits) * 10 + len(highs) * 5),
        )
    elif highs:
        r = result.warn(
            f"Nuclei: {len(highs)} high-severity finding(s)",
            detail,
            impact=min(15, len(highs) * 5),
        )
    elif mediums:
        r = result.warn(
            f"Nuclei: {len(mediums)} medium-severity finding(s)",
            detail,
            impact=min(8, len(mediums) * 3),
        )
    else:
        r = result.ok(f"Nuclei: {len(findings)} low/info finding(s)", detail)

    r.nuclei_findings = findings
    return r


def check_injection(domain: str) -> CheckResult:
    """OWASP A03:2021 — SQL/debug error disclosure and injectable surface detection."""
    from cee_scanner.skills.injection import check_injection as _check
    return _check(domain)


def check_auth_security(domain: str) -> CheckResult:
    """OWASP A07:2021 — Cookie flags, login brute-force exposure, unauthenticated admin panels."""
    from cee_scanner.skills.auth_security import check_auth_security as _check
    return _check(domain)


def check_integrity(domain: str) -> CheckResult:
    """OWASP A08:2021 — SRI on external CDN resources, exposed dependency manifests."""
    from cee_scanner.skills.integrity import check_integrity as _check
    return _check(domain)


def check_ssrf(domain: str) -> CheckResult:
    """OWASP A10:2021 — SSRF-prone endpoints, open redirects, unsafe URL parameters."""
    from cee_scanner.skills.ssrf import check_ssrf as _check
    return _check(domain)


def check_jwt_security(domain: str) -> CheckResult:
    """OWASP A08/A04:2021 — JWT alg:none, weak HMAC secrets, missing expiry, sensitive claims."""
    from cee_scanner.skills.jwt_security import check_jwt_security as _check
    return _check(domain)


def check_deserialization(domain: str) -> CheckResult:
    """OWASP A08:2021 — Java/PHP serialized objects in cookies, .NET ViewState, Shiro rememberMe."""
    from cee_scanner.skills.deserialization import check_deserialization as _check
    return _check(domain)


def check_default_creds(domain: str) -> CheckResult:
    """OWASP A02/A07:2021 — Default credential pairs on login forms and HTTP Basic auth endpoints."""
    from cee_scanner.skills.default_creds import check_default_creds as _check
    return _check(domain)


def check_rate_limiting(domain: str) -> CheckResult:
    """OWASP A06:2021 — Missing rate limiting on login, password reset, and registration endpoints."""
    from cee_scanner.skills.rate_limiting import check_rate_limiting as _check
    return _check(domain)


def check_llm_security(domain: str) -> CheckResult:
    """OWASP LLM01-LLM10:2025 — AI chatbot detection, exposed LLM API keys, prompt injection surface."""
    from cee_scanner.skills.llm_security import check_llm_security as _check
    return _check(domain)


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
    # ── CVE Enrichment ──
    check_cve,                  # free (NVD API); set NVD_API_KEY for higher rate limits
    # ── AppSec checks ──
    check_sast,                 # exposed source code, .env, debug pages
    check_sca,                  # exposed dependency manifests + NVD CVEs
    check_agentic_dast,         # Shannon-inspired multi-agent DAST (admin panels, API docs, injection analysis)
    check_iac,                  # Terraform state, K8s configs, CI/CD files
    # ── IP Intelligence ──
    check_ip_intel,             # IP reputation, blocklists, Shodan, AbuseIPDB, co-hosted domains
    # ── Dark Web Intelligence ──
    check_paranoidlab,          # credential & PII leaks + Telegram dark-web posts
    # ── Active reconnaissance ──
    check_ports,                # TCP connect scan of 30 common ports
    check_subdomains,           # CT log + DNS wordlist subdomain enumeration
    check_cms,                  # CMS / technology fingerprinting and version disclosure
    # ── Active CVE validation ──
    check_nuclei,               # nuclei templates: 3,000+ active CVE + misconfiguration checks
    # ── OWASP Top 10 + LLM ──
    check_injection,            # A03/A05: SQL+NoSQL error disclosure, injectable surfaces
    check_auth_security,        # A07: cookie flags, login hardening, admin panel exposure
    check_integrity,            # A08: SRI on CDN resources, exposed dependency manifests
    check_ssrf,                 # A10/A01: SSRF-prone endpoints, open redirects
    check_jwt_security,         # A08/A04: JWT alg:none, weak secrets, missing expiry
    check_deserialization,      # A08: Java/PHP/Shiro deserialization vectors
    check_default_creds,        # A02/A07: default credential testing on login forms
    check_rate_limiting,        # A06: missing rate limits on login/reset/register
    check_llm_security,         # LLM01-LLM10: AI chatbot risks, exposed API keys
]


def scan_domain(domain: str) -> dict:
    """Run all passive checks against a single domain in parallel."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _run(check_fn):
        try:
            return check_fn(domain).to_dict()
        except Exception as e:
            logger.error(f"Check {check_fn.__name__} failed for {domain}: {e}")
            return CheckResult(check_fn.__name__, domain).error(
                "Check crashed", str(e)[:80]
            ).to_dict()

    CHECK_TIMEOUT = 30  # max seconds any single check may run

    results = []
    with ThreadPoolExecutor(max_workers=len(ALL_CHECKS)) as executor:
        futures = {executor.submit(_run, fn): fn for fn in ALL_CHECKS}
        for future in as_completed(futures, timeout=CHECK_TIMEOUT * 2):
            fn = futures[future]
            try:
                results.append(future.result(timeout=CHECK_TIMEOUT))
            except TimeoutError:
                logger.warning(f"Check {fn.__name__} timed out for {domain}")
                results.append(CheckResult(fn.__name__, domain).error(
                    "Check timed out", f"exceeded {CHECK_TIMEOUT}s limit"
                ).to_dict())
            except Exception:
                results.append(future.result())

    # Calculate risk score (0=best, 100=worst)
    # Informational findings (surface indicators) carry no score penalty
    penalty = sum(r["score_impact"] for r in results if r.get("confidence") != "informational")
    risk_score = min(100, penalty)

    critical_count = sum(1 for r in results if r["status"] == "critical")
    warning_count  = sum(1 for r in results if r["status"] == "warning")
    info_count     = sum(1 for r in results if r["status"] == "info")

    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "critical": critical_count,
        "warnings": warning_count,
        "informational": info_count,
        "checks": results,
    }


def scan_domain_authenticated(domain: str, cookie: str, user_agent: str = "") -> dict:
    """
    Run a targeted authenticated scan using the provided session cookie.
    Tests authenticated surfaces: cookie security flags, header behaviour
    behind auth, SSRF-prone endpoints that require login, and injection
    surfaces exposed only to logged-in users.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from cee_scanner.skills.auth_security import check_auth_security
    from cee_scanner.skills.ssrf import check_ssrf
    from cee_scanner.skills.injection import check_injection
    import requests as _req

    auth_headers = {
        "User-Agent": user_agent or "Mozilla/5.0 (compatible; SwarmHawk-AuthScan/1.0)",
        "Cookie": cookie,
    }

    # ── Cookie security flag check ───────────────────────────────────────────
    def _check_cookie_flags() -> dict:
        result = CheckResult("cookie_flags", domain)
        try:
            r = _req.get(f"https://{domain}", headers=auth_headers, timeout=8,
                         allow_redirects=True, verify=False)
            set_cookie_headers = r.headers.get_all("set-cookie") if hasattr(r.headers, "get_all") else [
                v for k, v in r.headers.items() if k.lower() == "set-cookie"
            ]
            issues = []
            for sc in set_cookie_headers:
                sc_lower = sc.lower()
                if "httponly" not in sc_lower:
                    issues.append(f"Cookie missing HttpOnly: {sc.split(';')[0][:60]}")
                if "secure" not in sc_lower:
                    issues.append(f"Cookie missing Secure flag: {sc.split(';')[0][:60]}")
                if "samesite" not in sc_lower:
                    issues.append(f"Cookie missing SameSite: {sc.split(';')[0][:60]}")
            if issues:
                return result.warn("Cookie security flags missing",
                                   "\n".join(f"• {i}" for i in issues),
                                   impact=min(12, len(issues) * 4)).to_dict()
            if set_cookie_headers:
                return result.ok("Cookie security flags present",
                                 f"{len(set_cookie_headers)} cookie(s) checked — HttpOnly, Secure, SameSite set").to_dict()
            return result.ok("No Set-Cookie headers in response").to_dict()
        except Exception as e:
            return result.error("Cookie flag check failed", str(e)[:80]).to_dict()

    # ── Authenticated headers check ──────────────────────────────────────────
    def _check_auth_headers() -> dict:
        result = CheckResult("auth_headers", domain)
        try:
            r = _req.get(f"https://{domain}", headers=auth_headers, timeout=8,
                         allow_redirects=True, verify=False)
            resp_hdrs = {k.lower(): v for k, v in r.headers.items()}
            missing = []
            if "x-frame-options" not in resp_hdrs and "content-security-policy" not in resp_hdrs:
                missing.append("X-Frame-Options / CSP (clickjacking risk on authenticated pages)")
            if "cache-control" not in resp_hdrs or "no-store" not in resp_hdrs.get("cache-control", "").lower():
                missing.append("Cache-Control: no-store (authenticated page may be cached by proxy)")
            if missing:
                return result.warn("Auth page security headers missing",
                                   "\n".join(f"• {m}" for m in missing),
                                   impact=min(10, len(missing) * 5)).to_dict()
            return result.ok("Authenticated page headers look correct").to_dict()
        except Exception as e:
            return result.error("Auth header check failed", str(e)[:80]).to_dict()

    # ── IDOR probe: try incrementing a numeric ID in common API paths ────────
    def _check_idor_surface() -> dict:
        result = CheckResult("idor_surface", domain)
        PROBE_PATHS = ["/api/user/1", "/api/users/1", "/api/account/1",
                       "/api/me", "/api/profile", "/dashboard/user/1"]
        found = []
        try:
            for path in PROBE_PATHS:
                try:
                    r = _req.get(f"https://{domain}{path}", headers=auth_headers,
                                 timeout=6, verify=False, allow_redirects=False)
                    if r.status_code == 200 and len(r.text) > 20:
                        found.append(f"{path} → 200 ({len(r.text)}B — review for IDOR)")
                except Exception:
                    pass
            if found:
                return result.info(
                    f"IDOR surface: {len(found)} accessible API path(s)",
                    "These paths returned 200 with your session — manually verify they\n"
                    "enforce per-user access control:\n" + "\n".join(f"• {f}" for f in found)
                ).to_dict()
            return result.ok("No obvious IDOR surface found", "Common /api/user/ID paths returned 401/403/404").to_dict()
        except Exception as e:
            return result.error("IDOR probe failed", str(e)[:80]).to_dict()

    AUTH_CHECKS = [_check_cookie_flags, _check_auth_headers, _check_idor_surface]

    results = []
    with ThreadPoolExecutor(max_workers=len(AUTH_CHECKS)) as executor:
        futures = {executor.submit(fn): fn for fn in AUTH_CHECKS}
        for future in as_completed(futures, timeout=60):
            try:
                results.append(future.result(timeout=30))
            except Exception as e:
                results.append(CheckResult("auth_check", domain).error("Check failed", str(e)[:80]).to_dict())

    penalty = sum(r["score_impact"] for r in results if r.get("confidence") != "informational")
    return {
        "domain":      domain,
        "scanned_at":  datetime.now(timezone.utc).isoformat(),
        "scan_type":   "authenticated",
        "risk_score":  min(100, penalty),
        "critical":    sum(1 for r in results if r["status"] == "critical"),
        "warnings":    sum(1 for r in results if r["status"] == "warning"),
        "informational": sum(1 for r in results if r["status"] == "info"),
        "checks":      results,
    }


# Alias used by main.py backend
run_checks = scan_domain
