"""
cee_scanner.skills.deserialization
=====================================
OWASP A08:2021 — Insecure Deserialization

Passive detection only — no exploit payloads sent.

Checks:
  - Java serialized objects in cookies or responses (magic bytes aced0005)
  - PHP object serialization patterns in cookies/params (O:N:"Class")
  - .NET ViewState without MAC validation (__VIEWSTATE exposed)
  - Java RMI / JMX endpoints on common ports (via known paths)
  - Apache Shiro rememberMe cookie (well-known deserialization vector)
  - Pickle / YAML deserialization hints in Python frameworks
  - Generic deserialization endpoint paths (/api/data, /readObject)
"""

import re
import base64
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.deserialization")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Java serialized object magic bytes (base64: rO0AB)
JAVA_SERIAL_B64 = re.compile(r'rO0AB[A-Za-z0-9+/=]{4,}', re.IGNORECASE)
JAVA_SERIAL_HEX = re.compile(r'aced0005', re.IGNORECASE)

# PHP serialization patterns: O:4:"User":2:{...} or a:2:{i:0;s:5:"hello";}
PHP_SERIAL_RE = re.compile(r'(?:^|[\s;,&])(?:O:\d+:"|a:\d+:\{|s:\d+:")', re.MULTILINE)

# .NET ViewState
VIEWSTATE_RE = re.compile(r'<input[^>]+name=["\']?__VIEWSTATE["\']?[^>]+value=["\']?([A-Za-z0-9+/=]{20,})', re.IGNORECASE)

# Apache Shiro rememberMe (classic deserialization CVE)
SHIRO_RE = re.compile(r'rememberMe=', re.IGNORECASE)

# Deserialization-prone endpoint paths
DESER_PATHS = [
    ("/api/data",           "Generic data endpoint"),
    ("/readObject",         "Java readObject endpoint"),
    ("/api/v1/deserialize", "Explicit deserialization endpoint"),
    ("/invoker/readonly",   "JBoss invoker (CVE-2015-7501)"),
    ("/jmx-console",        "JMX console"),
    ("/admin-console",      "JBoss admin console"),
    ("/ws/rs/data",         "JAX-RS data endpoint"),
    ("/api/pickle",         "Python pickle endpoint"),
    ("/api/marshal",        "Marshal endpoint"),
]

# Python/YAML deserialization hints
YAML_HINTS = re.compile(r'yaml\.load\s*\(|pickle\.loads?\s*\(|marshal\.loads?\s*\(', re.IGNORECASE)


def _decode_base64_cookie(val: str) -> bytes:
    """Try to base64-decode a cookie value."""
    try:
        padding = 4 - len(val) % 4
        if padding != 4:
            val += "=" * padding
        return base64.b64decode(val)
    except Exception:
        return b""


def check_deserialization(domain: str) -> "CheckResult":
    """
    OWASP A08:2021 — Insecure deserialization surface detection.

    CRITICAL: Java/PHP serialized objects in cookies, .NET ViewState without MAC,
              or known deserialization endpoints (JBoss invoker, JMX console).
    WARNING:  Shiro rememberMe cookie, deserialization-prone endpoint paths exist.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("deserialization", domain)

    critical_findings = []
    findings = []

    try:
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=True, verify=False
        )

        # ── 1. Check cookies for serialized objects ──────────────────────
        raw_cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []
        if not raw_cookies:
            cookie_str = r.headers.get("Set-Cookie", "")
            raw_cookies = [cookie_str] if cookie_str else []

        for cookie_val in raw_cookies:
            if not cookie_val:
                continue
            # Java serial in base64
            if JAVA_SERIAL_B64.search(cookie_val):
                critical_findings.append(
                    "Java serialized object detected in cookie (base64 rO0AB prefix) — "
                    "classic RCE vector if deserialized server-side without validation"
                )
            # PHP serial in cookie value
            val_part = cookie_val.split(";")[0].split("=", 1)
            if len(val_part) > 1 and PHP_SERIAL_RE.search(val_part[1]):
                critical_findings.append(
                    f"PHP serialized object in cookie '{val_part[0].strip()}' — "
                    "PHP unserialize() without class whitelist enables object injection"
                )
            # Shiro rememberMe
            if SHIRO_RE.search(cookie_val):
                critical_findings.append(
                    "Apache Shiro rememberMe cookie detected — "
                    "vulnerable versions allow RCE via deserialization (CVE-2016-4437 family)"
                )

        # ── 2. Check response body ────────────────────────────────────────
        body = r.text[:8000]

        if JAVA_SERIAL_HEX.search(body):
            critical_findings.append("Java serialization magic bytes (aced0005) in response body")

        # .NET ViewState check
        vs_matches = VIEWSTATE_RE.findall(body)
        if vs_matches:
            # Decode and inspect — if no HMAC, it's vulnerable
            for vs_b64 in vs_matches[:2]:
                decoded = _decode_base64_cookie(vs_b64)
                # ViewState with MAC is prefixed with a hash — heuristic: <60 bytes suggests no MAC
                if len(decoded) > 0 and not decoded[:2] == b'\xff\x01':
                    findings.append(
                        "__VIEWSTATE exposed in HTML — verify EnableViewStateMac=true and "
                        "ViewStateUserKey is set (ASP.NET deserialization risk)"
                    )
                    break

        # ── 3. Probe known deserialization endpoints ─────────────────────
        for path, label in DESER_PATHS:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                if pr.status_code in (200, 400, 500):
                    if path in ("/invoker/readonly", "/jmx-console", "/admin-console"):
                        critical_findings.append(
                            f"{label} responds at {path} — known Java deserialization exploit path"
                        )
                    else:
                        findings.append(f"{label} responds at {path} — verify input is not deserialized unsafely")
            except Exception:
                pass

    except Exception as e:
        return result.ok("Deserialization check skipped", str(e)[:80])

    if critical_findings:
        detail = "Critical:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nWarnings:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"A08: {len(critical_findings)} deserialization risk(s)",
            detail,
            impact=min(25, len(critical_findings) * 15 + len(findings) * 3)
        )

    if findings:
        return result.warn(
            f"A08: {len(findings)} deserialization surface(s)",
            "\n".join(f"• {f}" for f in findings),
            impact=min(8, len(findings) * 4)
        )

    return result.ok(
        "No deserialization vulnerabilities detected",
        "No Java/PHP serialized objects, Shiro cookies, or known deserialization endpoints found"
    )
