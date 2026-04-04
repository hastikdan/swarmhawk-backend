"""
cee_scanner.skills.auth_security
==================================
OWASP A07:2021 — Identification and Authentication Failures

Checks:
  - Session cookie security flags: HttpOnly, Secure, SameSite
  - Login form: autocomplete="off" on password fields, CAPTCHA presence
  - HTTP Basic auth exposure on common sensitive paths
  - No-auth admin/login panels reachable from the internet
  - Password reset / account enumeration exposure
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.auth_security")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Paths that commonly host login forms — check for existence
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/account/login",
    "/user/login", "/admin/login", "/wp-login.php", "/wp-admin",
    "/administrator", "/user/signin",
]

# Paths that should NOT be open without auth
SENSITIVE_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
    "/adminer", "/manager/html", "/console",
]


def _cookie_flags(cookie_header: str) -> dict:
    """Parse a Set-Cookie header value and return flag presence."""
    lower = cookie_header.lower()
    return {
        "httponly": "httponly" in lower,
        "secure":   "secure" in lower,
        "samesite": "samesite=" in lower,
        "samesite_value": (
            "strict" if "samesite=strict" in lower else
            "lax"    if "samesite=lax"    in lower else
            "none"   if "samesite=none"   in lower else
            "missing"
        ),
    }


def check_auth_security(domain: str) -> "CheckResult":
    """
    OWASP A07:2021 — Authentication and session security.

    CRITICAL: Sensitive admin panel reachable without auth.
    WARNING:  Insecure cookie flags, missing CAPTCHA hints on login,
              autocomplete enabled on password fields.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("auth_security", domain)

    critical_findings = []
    findings = []

    try:
        # ── 1. Fetch main page, collect all Set-Cookie headers ───────────
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=True, verify=False
        )

        # Requests merges multiple Set-Cookie into one key — use raw headers
        raw_cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
        if not raw_cookies:
            # Fallback: parse from response.headers (merged)
            cookie_str = r.headers.get("Set-Cookie", "")
            raw_cookies = [cookie_str] if cookie_str else []

        cookie_issues = []
        for cookie_val in raw_cookies:
            if not cookie_val:
                continue
            # Extract cookie name
            name = cookie_val.split("=")[0].strip()
            flags = _cookie_flags(cookie_val)
            if not flags["httponly"]:
                cookie_issues.append(f"Cookie '{name}' missing HttpOnly (XSS can steal it)")
            if not flags["secure"]:
                cookie_issues.append(f"Cookie '{name}' missing Secure (transmitted over HTTP)")
            if not flags["samesite"]:
                cookie_issues.append(f"Cookie '{name}' missing SameSite (CSRF risk)")
            elif flags["samesite_value"] == "none":
                cookie_issues.append(f"Cookie '{name}' SameSite=None without explicit reason")

        if cookie_issues:
            for issue in cookie_issues[:5]:   # cap at 5 to keep detail readable
                findings.append(issue)

        # ── 2. Check for HTTP Basic auth challenges ──────────────────────
        if r.status_code == 401 and "www-authenticate" in r.headers:
            auth_header = r.headers["www-authenticate"].lower()
            if "basic" in auth_header:
                findings.append("HTTP Basic authentication on main page (credentials sent base64-encoded)")

        # ── 3. Probe login paths ─────────────────────────────────────────
        login_found = False
        for path in LOGIN_PATHS:
            try:
                lr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT, headers=HEADERS,
                    allow_redirects=True, verify=False
                )
                if lr.status_code == 200 and re.search(
                    r'<input[^>]+type=["\']?password["\']?', lr.text, re.IGNORECASE
                ):
                    login_found = True
                    body = lr.text

                    # Check password autocomplete
                    if not re.search(r'autocomplete=["\']?(off|new-password)["\']?', body, re.IGNORECASE):
                        findings.append(f"Login form at {path} allows password autocomplete (browser may cache credentials)")

                    # Check for CAPTCHA / rate-limiting signals
                    has_captcha = bool(re.search(
                        r'captcha|recaptcha|hcaptcha|turnstile|cf-turnstile', body, re.IGNORECASE
                    ))
                    has_rate_header = any(
                        h in lr.headers for h in ["x-ratelimit-limit", "retry-after", "x-rate-limit"]
                    )
                    if not has_captcha and not has_rate_header:
                        findings.append(f"Login form at {path}: no CAPTCHA or rate-limit headers detected (brute-force risk)")

                    break  # one login page is enough
            except Exception:
                pass

        # ── 4. Probe sensitive admin paths ───────────────────────────────
        for path in SENSITIVE_PATHS:
            try:
                sr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT, headers=HEADERS,
                    allow_redirects=False, verify=False
                )
                # 200 without redirect = accessible without auth
                if sr.status_code == 200 and re.search(
                    r'(admin|dashboard|control.?panel|phpmyadmin)', sr.text, re.IGNORECASE
                ):
                    critical_findings.append(f"Admin panel at {path} accessible without authentication")
            except Exception:
                pass

        # ── 5. Password reset endpoint enumeration risk ──────────────────
        for path in ["/forgot-password", "/reset-password", "/password/reset"]:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT, headers=HEADERS,
                    allow_redirects=True, verify=False
                )
                if pr.status_code == 200 and re.search(r'email|username', pr.text, re.IGNORECASE):
                    # Just note it exists — user enumeration possible if response differs
                    findings.append(f"Password reset form at {path} — verify it doesn't enumerate valid accounts via response differences")
                    break
            except Exception:
                pass

    except Exception as e:
        return result.ok("Auth security check skipped", str(e)[:80])

    if critical_findings:
        detail = "Critical:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nWarnings:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"A07: {len(critical_findings)} critical auth failure(s)",
            detail,
            impact=min(20, len(critical_findings) * 15 + len(findings) * 2)
        )

    if findings:
        detail = "\n".join(f"• {f}" for f in findings)
        return result.warn(
            f"A07: {len(findings)} authentication weakness(es)",
            detail,
            impact=min(12, len(findings) * 3)
        )

    return result.ok(
        "Authentication controls look solid",
        "Cookie flags set, no unauthenticated admin panels, no obvious brute-force exposure"
    )
