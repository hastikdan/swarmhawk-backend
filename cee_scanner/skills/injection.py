"""
cee_scanner.skills.injection
=============================
OWASP A03:2021 — Injection Surface Detection

Passive + safe probing only — no actual exploit payloads sent.

Checks:
  - SQL / ORM error patterns in HTTP responses (verbose error disclosure)
  - Debug mode / stack trace disclosure on main page and error responses
  - Count of injectable input surfaces (text, search, textarea forms)
  - Error verbosity on crafted 404 paths
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.injection")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Patterns indicating SQL/ORM errors are leaking to the client
SQL_ERROR_PATTERNS = [
    (r"you have an error in your sql syntax",          "MySQL syntax error disclosed"),
    (r"warning.*mysqli?_",                             "PHP MySQL warning disclosed"),
    (r"unclosed quotation mark after the character",   "MS SQL error disclosed"),
    (r"quoted string not properly terminated",         "Oracle SQL error disclosed"),
    (r"ora-\d{5}",                                     "Oracle error code disclosed"),
    (r"pg::.*error|postgresql.*error|psycopg2",        "PostgreSQL error disclosed"),
    (r"sqlite3?::.*exception|sqlite.*error",           "SQLite error disclosed"),
    (r"com\.mysql\.jdbc|jdbc.*exception",              "Java JDBC SQL error disclosed"),
    (r"system\.data\.sqlclient",                       ".NET SQL error disclosed"),
    (r"invalid column name|invalid object name",       "MS SQL schema info disclosed"),
]

# Debug / stack-trace patterns
DEBUG_PATTERNS = [
    (r"traceback \(most recent call last\)",            "Python traceback disclosed"),
    (r"werkzeug debugger|werkzeug\.debug",              "Werkzeug interactive debugger exposed"),
    (r"django\.debug|debug = true",                     "Django debug mode active"),
    (r"laravel whoops|whoops!.*exception",              "Laravel Whoops error handler exposed"),
    (r"ruby on rails.*exception|activerecord.*error",   "Rails exception disclosed"),
    (r"exception in thread.*main|java\.lang\.",         "Java stack trace disclosed"),
    (r"at .*\.(java|kt|scala):\d+",                     "JVM stack frame disclosed"),
    (r"microsoft .*net framework.*error",               ".NET framework error page"),
    (r"server error in '/' application",                "ASP.NET yellow screen of death"),
    (r"phpdebugbar|symfony debug toolbar",              "PHP/Symfony debug toolbar exposed"),
]


def check_injection(domain: str) -> "CheckResult":
    """
    OWASP A03:2021 — Injection surface detection.

    CRITICAL: SQL/ORM errors or interactive debugger exposed in responses.
    WARNING:  Debug info, stack traces, or multiple unprotected input surfaces.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("injection", domain)

    findings = []
    critical_findings = []

    def _scan_body(body: str, context: str):
        lower = body.lower()
        for pattern, label in SQL_ERROR_PATTERNS:
            if re.search(pattern, lower):
                critical_findings.append(f"{label} ({context})")
        for pattern, label in DEBUG_PATTERNS:
            if re.search(pattern, lower):
                # Werkzeug interactive debugger is critical; others are warnings
                if "werkzeug" in pattern or "debug = true" in pattern:
                    critical_findings.append(f"{label} ({context})")
                else:
                    findings.append(f"{label} ({context})")

    try:
        # ── 1. Fetch main page ───────────────────────────────────────────
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=True, verify=False
        )
        _scan_body(r.text, "homepage")

        # Count injectable input surfaces
        inputs = re.findall(
            r'<input[^>]+type=["\']?(text|search|email|url|tel|number)["\']?',
            r.text, re.IGNORECASE
        )
        textareas = re.findall(r'<textarea', r.text, re.IGNORECASE)
        injectable = len(inputs) + len(textareas)
        if injectable >= 3:
            findings.append(f"{injectable} injectable input field(s) on homepage (text/textarea/email)")

        # ── 2. Probe a safe 404 path for verbose error pages ─────────────
        try:
            err_r = requests.get(
                f"https://{domain}/swarmhawk-probe-404-xyz",
                timeout=TIMEOUT, headers=HEADERS, verify=False,
                allow_redirects=False
            )
            if err_r.status_code != 301:
                _scan_body(err_r.text, "404 error page")
        except Exception:
            pass

        # ── 3. Probe /api/v1 for JSON stack traces ───────────────────────
        for api_path in ["/api", "/api/v1", "/graphql"]:
            try:
                api_r = requests.get(
                    f"https://{domain}{api_path}",
                    timeout=TIMEOUT, headers=HEADERS, verify=False,
                    allow_redirects=False
                )
                if api_r.status_code < 500:
                    continue
                _scan_body(api_r.text, f"API endpoint {api_path}")
            except Exception:
                pass

    except Exception as e:
        return result.ok("Injection check skipped", str(e)[:80])

    if critical_findings:
        detail = "Critical findings:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nAdditional indicators:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"A03: {len(critical_findings)} critical injection indicator(s)",
            detail,
            impact=min(20, len(critical_findings) * 10 + len(findings) * 3)
        )

    if findings:
        detail = "\n".join(f"• {f}" for f in findings)
        return result.warn(
            f"A03: {len(findings)} injection surface indicator(s)",
            detail,
            impact=min(10, len(findings) * 3)
        )

    return result.ok(
        "No injection surfaces detected",
        f"No SQL errors, debug traces, or excessive input exposure found"
    )
