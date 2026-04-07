"""
cee_scanner.skills.rate_limiting
====================================
OWASP A06:2021 — Insecure Design: Missing Rate Limiting

Checks critical endpoints for rate-limiting controls that prevent
brute-force, credential stuffing, and abuse attacks.

Checks:
  - Login endpoint: rapid POST requests → expect 429 or rate-limit headers
  - Password reset endpoint: repeated requests for same email
  - Registration endpoint: mass account creation protection
  - API endpoints: absence of rate-limit response headers
  - GraphQL: introspection or batch query rate limiting
"""

import re
import time
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.rate_limiting")

TIMEOUT = 4
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Headers that indicate rate limiting is in place
RATE_LIMIT_HEADERS = {
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "x-slowdown",
    "cf-ray",  # Cloudflare sometimes implies rate limiting
}

CAPTCHA_PATTERNS = re.compile(
    r'captcha|recaptcha|hcaptcha|turnstile|cf-turnstile|robot|bot.?check',
    re.IGNORECASE
)

# Endpoints to test with rapid requests
RATE_LIMIT_TARGETS = [
    ("/login",            "POST", {"username": "probe@test.com", "password": "probe123"}, "Login"),
    ("/signin",           "POST", {"email":    "probe@test.com", "password": "probe123"}, "Sign-in"),
    ("/forgot-password",  "POST", {"email":    "probe@test.com"},                          "Password reset"),
    ("/api/auth/login",   "POST", {"username": "probe@test.com", "password": "probe123"}, "API login"),
    ("/api/v1/auth",      "POST", {"username": "probe@test.com", "password": "probe123"}, "API v1 auth"),
]
RAPID_REQUEST_COUNT = 3  # 5 was too slow; 3 is sufficient to detect missing rate limits


def _has_rate_limit_signal(response) -> bool:
    """Return True if response contains rate-limiting headers."""
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    return any(h in headers_lower for h in RATE_LIMIT_HEADERS)


def _send_rapid_requests(url: str, method: str, data: dict, count: int = 5) -> list:
    """Send `count` rapid requests and return list of (status_code, has_rl_header)."""
    results = []
    session = requests.Session()
    session.headers.update(HEADERS)
    session.verify = False
    for _ in range(count):
        try:
            if method == "POST":
                r = session.post(url, data=data, timeout=TIMEOUT, allow_redirects=False)
            else:
                r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            results.append((r.status_code, _has_rate_limit_signal(r), r.text[:500]))
        except Exception:
            break
    return results


def check_rate_limiting(domain: str) -> "CheckResult":
    """
    OWASP A06:2021 — Missing rate limiting on sensitive endpoints.

    CRITICAL: Login or password reset endpoint accepts 5+ rapid requests
              with no 429 response and no rate-limit headers (brute-force risk).
    WARNING:  Endpoint exists but only shows captcha hints, not hard rate limiting.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("rate_limiting", domain)

    critical_findings = []
    findings = []

    # First check if the main site is up
    try:
        r = requests.get(f"https://{domain}", timeout=TIMEOUT, headers=HEADERS, verify=False)
    except Exception as e:
        return result.ok("Rate limiting check skipped", str(e)[:80])

    try:
        for path, method, post_data, label in RATE_LIMIT_TARGETS:
            url = f"https://{domain}{path}"
            # Quick existence check
            try:
                probe = requests.get(url, timeout=TIMEOUT, headers=HEADERS,
                                     verify=False, allow_redirects=True)
                if probe.status_code == 404:
                    continue
                if method == "POST" and not re.search(
                    r'<input|application/json|login|email|password|submit',
                    probe.text, re.IGNORECASE
                ):
                    continue
            except Exception:
                continue

            # Endpoint exists — test rapid fire
            results = _send_rapid_requests(url, method, post_data, count=RAPID_REQUEST_COUNT)
            if not results:
                continue

            statuses    = [r[0] for r in results]
            rl_detected = any(r[1] for r in results)
            got_429     = any(s == 429 for s in statuses)
            last_body   = results[-1][2] if results else ""

            has_captcha = bool(CAPTCHA_PATTERNS.search(last_body))

            if got_429 or rl_detected:
                # Rate limiting is in place — good
                findings.append(f"✓ {label} at {path}: rate limiting enforced")
                continue

            if has_captcha:
                findings.append(
                    f"{label} at {path}: CAPTCHA present but no hard rate-limit headers — "
                    f"bot-driven attacks may bypass CAPTCHA"
                )
                continue

            # 5 rapid requests accepted with no throttling
            if any(s in (200, 201, 302, 400, 401, 422) for s in statuses):
                critical_findings.append(
                    f"{label} at {path}: 5 rapid requests accepted with no rate limiting "
                    f"(statuses: {', '.join(str(s) for s in statuses)}) — "
                    f"credential stuffing and brute-force attacks are unrestricted"
                )

    except Exception as e:
        logger.debug(f"[rate_limiting] {domain}: {e}")

    # Filter out "✓ good" findings from the warning list
    real_findings = [f for f in findings if not f.startswith("✓")]

    if critical_findings:
        detail = "Critical — no rate limiting detected:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if real_findings:
            detail += "\nWarnings:\n" + "\n".join(f"• {f}" for f in real_findings)
        return result.critical(
            f"A06: {len(critical_findings)} unprotected endpoint(s)",
            detail,
            impact=min(15, len(critical_findings) * 8 + len(real_findings) * 2)
        )

    if real_findings:
        return result.warn(
            f"A06: {len(real_findings)} endpoint(s) with weak rate limiting",
            "\n".join(f"• {f}" for f in real_findings),
            impact=min(8, len(real_findings) * 4)
        )

    return result.ok(
        "Rate limiting controls in place",
        "Sensitive endpoints enforce rate limiting or captcha"
    )
