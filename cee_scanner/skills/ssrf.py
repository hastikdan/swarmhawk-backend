"""
cee_scanner.skills.ssrf
=========================
OWASP A10:2021 — Server-Side Request Forgery (SSRF) Detection

Safe, passive-first approach — no actual SSRF payloads sent to internal
addresses. Detects SSRF-prone patterns and open-redirect vulnerabilities
that are stepping stones to SSRF exploitation.

Checks:
  - SSRF-prone endpoint paths (proxy, fetch, url, redirect, image, download)
  - URL/redirect parameters in page links (?url=, ?link=, ?next=, ?return=)
  - Open redirect confirmation (301/302 to external host on crafted requests)
  - Webhook / callback endpoints that accept arbitrary URLs
"""

import re
import urllib.parse
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.ssrf")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Endpoint paths commonly associated with SSRF vulnerabilities
SSRF_PRONE_PATHS = [
    "/proxy",
    "/fetch",
    "/url",
    "/open",
    "/redirect",
    "/link",
    "/out",
    "/outgoing",
    "/external",
    "/image",
    "/img",
    "/download",
    "/load",
    "/api/proxy",
    "/api/fetch",
    "/api/redirect",
    "/api/image",
    "/webhook",
    "/callback",
    "/hook",
    "/integrations/webhook",
    "/share",
    "/preview",
]

# URL-like query parameter names that may accept arbitrary URLs
URL_PARAM_PATTERNS = re.compile(
    r'[?&](url|link|redirect|next|return|returnUrl|return_url|goto|dest|'
    r'destination|target|source|src|feed|path|image|img|file|uri|href|'
    r'callback|webhook|endpoint)=',
    re.IGNORECASE
)


def _is_open_redirect(domain: str, path: str) -> bool:
    """
    Test whether a path + redirect param redirects to an external host.
    Uses example.com as the redirect target — safe, no internal IPs.
    """
    probe_url = f"https://{domain}{path}?url=https://example.com&next=https://example.com&redirect=https://example.com"
    try:
        r = requests.get(
            probe_url, timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=False, verify=False
        )
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            if location and "example.com" in location:
                return True
    except Exception:
        pass
    return False


def check_ssrf(domain: str) -> "CheckResult":
    """
    OWASP A10:2021 — Server-Side Request Forgery surface detection.

    CRITICAL: Confirmed open redirect (stepping stone to SSRF/phishing).
    WARNING:  SSRF-prone endpoints exist, or URL parameters found in page links.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("ssrf", domain)

    critical_findings = []
    findings = []
    ssrf_prone_found = []

    try:
        # ── 1. Fetch homepage, look for URL parameters in links ──────────
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=True, verify=False
        )
        url_params = URL_PARAM_PATTERNS.findall(r.text)
        unique_params = list(dict.fromkeys(p.lower() for p in url_params))
        if unique_params:
            findings.append(
                f"URL-accepting parameter(s) in page links: {', '.join(unique_params[:8])}"
                f" — verify server-side URL validation is enforced"
            )

        # ── 2. Probe SSRF-prone paths (just check existence, no payloads) ─
        for path in SSRF_PRONE_PATHS:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                # 200 or 4xx (not 404 specifically) suggests endpoint exists
                if pr.status_code in (200, 400, 401, 403, 405, 422, 429, 500):
                    ssrf_prone_found.append(path)
            except Exception:
                pass

        if ssrf_prone_found:
            findings.append(
                f"{len(ssrf_prone_found)} SSRF-prone endpoint(s) exist: "
                + ", ".join(ssrf_prone_found[:8])
            )

        # ── 3. Test top SSRF-prone paths for open redirects ──────────────
        redirect_tested = 0
        for path in ssrf_prone_found[:5] + ["/redirect", "/out", "/"]:
            if redirect_tested >= 5:
                break
            if _is_open_redirect(domain, path):
                critical_findings.append(
                    f"Open redirect confirmed at {path} — redirects to attacker-controlled URLs "
                    f"(enables phishing and SSRF pivoting)"
                )
            redirect_tested += 1

        # ── 4. Check for webhook endpoints accepting arbitrary URLs ───────
        webhook_paths = [p for p in ssrf_prone_found if "webhook" in p or "callback" in p or "hook" in p]
        if webhook_paths:
            findings.append(
                f"Webhook/callback endpoint(s) found: {', '.join(webhook_paths)} "
                f"— ensure URL allowlist is enforced server-side"
            )

    except Exception as e:
        return result.ok("SSRF check skipped", str(e)[:80])

    if critical_findings:
        detail = "Critical:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nAdditional risk surface:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"A10: {len(critical_findings)} SSRF/redirect issue(s)",
            detail,
            impact=min(20, len(critical_findings) * 12 + len(findings) * 3)
        )

    if findings:
        detail = "\n".join(f"• {f}" for f in findings)
        return result.warn(
            f"A10: {len(findings)} SSRF surface indicator(s)",
            detail,
            impact=min(10, len(findings) * 4)
        )

    return result.ok(
        "No SSRF surfaces detected",
        "No SSRF-prone endpoints, open redirects, or unsafe URL parameters found"
    )
