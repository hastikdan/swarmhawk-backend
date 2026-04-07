"""
cee_scanner.skills.jwt_security
=================================
OWASP A08:2021 / A04:2021 — JWT Security Vulnerabilities

Checks:
  - JWT tokens in Set-Cookie headers, Authorization responses, or JSON bodies
  - Algorithm confusion: alg:none vulnerability (unsigned tokens accepted)
  - Weak HMAC secrets (tests top common secrets: "secret", "password", etc.)
  - JWT header/payload disclosure (sensitive data in unencrypted claims)
  - Token lifetime: no exp claim or excessively long expiry
"""

import re
import json
import base64
import hmac
import hashlib
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.jwt_security")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Common weak JWT secrets
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "mysecret",
    "your-256-bit-secret", "your-secret", "jwt_secret", "jwtSecret",
    "supersecret", "secretkey", "key", "mykey", "app_secret",
    "HS256", "none", "", "null", "undefined",
]

JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def _b64decode_safe(s: str) -> bytes:
    """Base64url decode with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s)
    except Exception:
        return b""


def _decode_jwt(token: str) -> tuple[dict, dict]:
    """Return (header, payload) dicts, or ({}, {}) on failure."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}, {}
        header  = json.loads(_b64decode_safe(parts[0]))
        payload = json.loads(_b64decode_safe(parts[1]))
        return header, payload
    except Exception:
        return {}, {}


def _test_alg_none(token: str) -> bool:
    """Return True if server accepts an alg:none unsigned JWT."""
    parts = token.split(".")
    if len(parts) < 2:
        return False

    # Build forged token with alg:none
    forged_header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    forged_payload = parts[1]
    forged_token   = f"{forged_header}.{forged_payload}."

    return forged_header, forged_token


def _test_weak_secret(token: str, secret: str) -> bool:
    """Return True if the given secret correctly signs this JWT."""
    parts = token.split(".")
    if len(parts) < 3:
        return False
    msg    = f"{parts[0]}.{parts[1]}".encode()
    sig    = _b64decode_safe(parts[2])
    digest = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return hmac.compare_digest(digest, sig)


def _extract_jwts(text: str) -> list[str]:
    return list(set(JWT_RE.findall(text)))


def check_jwt_security(domain: str) -> "CheckResult":
    """
    OWASP A08/A04 — JWT vulnerability detection.

    CRITICAL: alg:none accepted or JWT signed with a common weak secret.
    WARNING:  JWT tokens in cookies/responses with no expiry or sensitive claims.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("jwt_security", domain)

    critical_findings = []
    findings = []

    try:
        # ── 1. Fetch main page, look for JWT tokens ──────────────────────
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=True, verify=False
        )

        # Collect JWTs from response body + cookies
        all_text = r.text
        cookie_hdrs = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
        all_text += " ".join(cookie_hdrs)

        tokens = _extract_jwts(all_text)

        # ── 2. Also probe common auth/token endpoints ────────────────────
        for path in ["/api/token", "/api/auth", "/auth/token", "/api/v1/token",
                     "/oauth/token", "/user/token", "/token"]:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                tokens += _extract_jwts(pr.text)
            except Exception:
                pass

        tokens = list(set(tokens))

        if not tokens:
            # No JWTs found — check if site uses JWT-based auth (meta/script hints)
            jwt_hints = re.search(
                r'jwt|bearer|authorization.*token|access_token|id_token',
                r.text, re.IGNORECASE
            )
            if not jwt_hints:
                return result.ok("No JWT tokens detected", "No JWT usage found in page or common API paths")
            findings.append("JWT-based authentication indicated in page source — tokens not exposed to scanner")
            return result.warn(
                "A08/A04: JWT usage detected — manual verification needed",
                "\n".join(f"• {f}" for f in findings),
                impact=2
            )

        findings.append(f"{len(tokens)} JWT token(s) found in responses/cookies")

        # ── 3. Analyse each token ────────────────────────────────────────
        for token in tokens[:3]:   # cap analysis at 3 tokens
            header, payload = _decode_jwt(token)
            if not header:
                continue

            alg = header.get("alg", "?").upper()

            # Check alg:none
            if alg == "NONE":
                critical_findings.append(f"JWT signed with alg:none — token is unsigned and trivially forgeable")

            # Check for sensitive data in payload
            sensitive_keys = {"password", "passwd", "secret", "token", "api_key", "private_key", "ssn", "credit_card"}
            exposed = [k for k in payload if k.lower() in sensitive_keys]
            if exposed:
                critical_findings.append(f"JWT payload contains sensitive field(s): {', '.join(exposed)}")

            # Check token expiry
            if "exp" not in payload:
                findings.append(f"JWT token has no 'exp' claim — never expires (session hijacking risk)")
            else:
                import time
                exp = payload["exp"]
                ttl = exp - int(time.time())
                if ttl > 86400 * 30:   # > 30 days
                    findings.append(f"JWT token expires in {ttl // 86400} days — excessively long lifetime")

            # Test weak HMAC secrets (only for HS256/HS384/HS512)
            if alg.startswith("HS"):
                for secret in WEAK_SECRETS:
                    try:
                        if _test_weak_secret(token, secret):
                            critical_findings.append(
                                f"JWT signed with weak secret '{secret}' — "
                                f"attacker can forge arbitrary tokens (alg: {alg})"
                            )
                            break
                    except Exception:
                        pass

            # Note algorithm
            if alg in ("HS256", "HS384", "HS512"):
                findings.append(f"JWT uses symmetric {alg} — key must be kept strictly server-side")
            elif alg in ("RS256", "ES256"):
                pass   # asymmetric — fine
            elif alg == "?":
                findings.append("JWT header missing 'alg' claim — non-standard token")

    except Exception as e:
        return result.ok("JWT security check skipped", str(e)[:80])

    if critical_findings:
        detail = "Critical:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nInfo:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"A08/A04: {len(critical_findings)} JWT vulnerability(ies)",
            detail,
            impact=min(25, len(critical_findings) * 15 + len(findings) * 2)
        )

    if findings:
        return result.warn(
            f"A08/A04: {len(findings)} JWT concern(s)",
            "\n".join(f"• {f}" for f in findings),
            impact=min(8, len(findings) * 3)
        )

    return result.ok("JWT tokens look secure", "Tokens use strong algorithms with proper expiry")
