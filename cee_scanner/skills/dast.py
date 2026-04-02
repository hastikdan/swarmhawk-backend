"""
cee_scanner.skills.dast
=======================
DAST (Dynamic Application Security Testing) Check

Performs passive/light active probing to detect common web vulnerabilities
and misconfigurations in running applications.

Tests:
  - Exposed admin panels (unauthenticated access)
  - Exposed API documentation (Swagger / OpenAPI)
  - Directory listing enabled
  - Exposed CI/CD and deployment artifacts
  - Default credential pages
  - Error pages leaking stack traces / framework info
  - Open redirect indicators in URL parameters
  - Exposed metrics / monitoring endpoints
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.dast")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}


# (path, label, severity, confirm_pattern)
# severity: "critical" | "warning"
DAST_PROBES = [
    # ── Admin panels ─────────────────────────────────────────────────────────
    ("/admin",               "Admin panel exposed",                "warning",  r'login|password|username|sign.?in|dashboard|panel|admin'),
    ("/admin/login",         "Admin login page exposed",           "warning",  r'login|password|username|sign.?in'),
    ("/administrator",       "Administrator panel exposed",        "warning",  r'login|password|username|sign.?in|dashboard|panel'),
    ("/wp-admin/",           "WordPress admin panel exposed",      "warning",  r"wp-admin|WordPress"),
    ("/phpmyadmin/",         "phpMyAdmin exposed",                 "critical", r"phpMyAdmin|pma_username"),
    ("/phpmyadmin",          "phpMyAdmin exposed",                 "critical", r"phpMyAdmin|pma_username"),
    ("/pma/",                "phpMyAdmin (pma) exposed",           "critical", r"phpMyAdmin"),
    ("/adminer.php",         "Adminer DB UI exposed",              "critical", r"Adminer|adminer"),
    ("/adminer",             "Adminer DB UI exposed",              "critical", r"Adminer|adminer"),

    # ── API documentation ────────────────────────────────────────────────────
    ("/swagger.json",        "Swagger API docs exposed",           "warning",  r'"swagger"|"openapi"'),
    ("/swagger.yaml",        "Swagger API docs exposed",           "warning",  r'swagger:|openapi:'),
    ("/swagger-ui.html",     "Swagger UI exposed",                 "warning",  r'swagger|Swagger'),
    ("/swagger-ui/",         "Swagger UI exposed",                 "warning",  r'swagger|Swagger'),
    ("/api-docs",            "API docs exposed",                   "warning",  r'"swagger"|"openapi"|"paths"|"info"'),
    ("/api-docs/",           "API docs exposed",                   "warning",  r'"swagger"|"openapi"|"paths"|"info"'),
    ("/openapi.json",        "OpenAPI spec exposed",               "warning",  r'"openapi"'),
    ("/openapi.yaml",        "OpenAPI spec exposed",               "warning",  r'openapi:'),
    ("/v1/api-docs",         "API v1 docs exposed",                "warning",  r'"swagger"|"openapi"|"paths"'),
    ("/v2/api-docs",         "API v2 docs exposed",                "warning",  r'"swagger"|"openapi"|"paths"'),
    ("/graphql",             "GraphQL endpoint exposed",           "warning",  r'GraphQL|__schema'),
    ("/graphiql",            "GraphiQL IDE exposed",               "warning",  r'graphiql|GraphiQL'),

    # ── Exposed data / backups ──────────────────────────────────────────────
    ("/robots.txt",          "robots.txt (check for hidden paths)","warning",  r'Disallow:\s*/[a-z]'),
    ("/sitemap.xml",         "Sitemap found",                      "warning",  None),  # info only

    # ── Monitoring / metrics ─────────────────────────────────────────────────
    ("/metrics",             "Prometheus metrics exposed",         "warning",  r'# HELP|# TYPE|go_gc'),
    ("/actuator",            "Spring Boot actuator exposed",       "critical", r'actuator|Spring'),
    ("/actuator/env",        "Spring Boot env actuator exposed",   "critical", r'propertySources|activeProfiles'),
    ("/actuator/health",     "Spring Boot health exposed",         "warning",  r'"status"'),
    ("/_cat/indices",        "Elasticsearch indices exposed",      "critical", r'health.*status|green|yellow'),
    ("/solr/",               "Apache Solr exposed",                "critical", r'Solr Admin|solr'),

    # ── Directory listing ────────────────────────────────────────────────────
    ("/uploads/",            "Uploads directory listing",          "warning",  r'Index of|<a href'),
    ("/files/",              "Files directory listing",            "warning",  r'Index of|<a href'),
    ("/static/",             "Static directory listing",           "warning",  r'Index of|<a href'),
    ("/backup/",             "Backup directory listing",           "critical", r'Index of|<a href'),

    # ── CI/CD and build artifacts ────────────────────────────────────────────
    ("/Jenkinsfile",         "Jenkinsfile exposed",                "warning",  r'pipeline|agent|stages'),
    ("/.travis.yml",         "Travis CI config exposed",           "warning",  r'language:|script:'),
    ("/Dockerfile",          "Dockerfile exposed",                 "warning",  r'FROM |RUN |COPY '),
    ("/docker-compose.yml",  "Docker Compose config exposed",      "warning",  r'version:|services:'),
    ("/docker-compose.yaml", "Docker Compose config exposed",      "warning",  r'version:|services:'),
]

# Paths to test for open redirect
REDIRECT_PARAMS = [
    "/?url=https://evil.com",
    "/?redirect=https://evil.com",
    "/?next=https://evil.com",
    "/?return=https://evil.com",
    "/?returnUrl=https://evil.com",
]

# Patterns that indicate a stack trace in error pages
STACK_TRACE_PATTERNS = [
    r"at\s+[\w\.]+\([\w\.]+:\d+\)",    # Java stack trace
    r"Traceback \(most recent call",    # Python
    r"Fatal error:.*on line \d+",       # PHP
    r"System\.Exception:",              # .NET
    r"ActiveRecord::.*Error",           # Rails
]


def _check_open_redirect(domain: str) -> str | None:
    """Test for open redirect vulnerability."""
    for path in REDIRECT_PARAMS[:3]:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(
                url, timeout=TIMEOUT, headers=HEADERS,
                allow_redirects=False, verify=False,
            )
            # 3xx redirect to external domain = open redirect
            # Must redirect TO evil.com (as the destination host), not merely
            # preserve evil.com in the query string of a canonical redirect.
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if re.match(r'https?://evil\.com', loc) or loc.startswith("//evil.com"):
                    m = re.search(r'\?(\w+)=', path)
                    param = f"?{m.group(1)}" if m else "redirect parameter"
                    return f"Open Redirect — server follows attacker-controlled URLs (via '{param}' parameter)"
        except Exception:
            pass
    return None


def _check_stack_trace(domain: str) -> str | None:
    """Test if error pages leak stack traces."""
    test_paths = [
        "/nonexistent_path_xyz_12345",
        "/api/nonexistent",
        "/index.php?id=1'",
    ]
    for path in test_paths:
        try:
            r = requests.get(
                f"https://{domain}{path}", timeout=TIMEOUT,
                headers=HEADERS, allow_redirects=True, verify=False,
            )
            body = r.text[:3000]
            for pattern in STACK_TRACE_PATTERNS:
                if re.search(pattern, body):
                    return "Error page leaks stack trace / framework details"
        except Exception:
            pass
    return None


def check_dast(domain: str) -> "CheckResult":
    """
    DAST — probe for exposed admin panels, API docs, monitoring endpoints,
    open redirects, and verbose error pages.

    Returns CRITICAL for database UIs, actuators, or open redirects.
    WARNING for admin panels, API docs, and directory listings.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("dast", domain)

    critical_findings = []
    warning_findings  = []

    # Probe static paths
    for path, label, severity, confirm_pat in DAST_PROBES:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(
                url, timeout=TIMEOUT, headers=HEADERS,
                allow_redirects=True, verify=False,
            )
            if r.status_code not in (200, 206):
                continue

            body = r.text[:3000]

            # Empty body → catch-all route, not a real endpoint
            if len(body.strip()) < 100:
                continue

            if confirm_pat and not re.search(confirm_pat, body, re.IGNORECASE):
                continue

            # robots.txt: only flag if it disallows interesting paths
            if path == "/robots.txt":
                hidden = re.findall(r'Disallow:\s*(/[^\s]+)', body)
                hidden = [h for h in hidden if len(h) > 1]
                if hidden:
                    warning_findings.append(
                        f"robots.txt reveals {len(hidden)} hidden path(s): {', '.join(hidden[:5])}"
                    )
                continue

            # sitemap: informational only, skip
            if path == "/sitemap.xml":
                continue

            logger.info(f"DAST: {label} at {url}")
            if severity == "critical":
                critical_findings.append(f"{label} ({path})")
            else:
                warning_findings.append(f"{label} ({path})")

        except Exception:
            continue

    # Check for open redirect
    redirect = _check_open_redirect(domain)
    if redirect:
        critical_findings.append(redirect)

    # Check for stack traces in error pages
    stack = _check_stack_trace(domain)
    if stack:
        warning_findings.append(stack)

    all_findings = critical_findings + warning_findings

    if not all_findings:
        return result.ok(
            "DAST: no exposed panels, APIs, or misconfigurations found",
            "No admin panels, API docs, monitoring endpoints, or open redirects detected"
        )

    detail = ""
    if critical_findings:
        detail += "Critical findings:\n" + "\n".join(f"  • {f}" for f in critical_findings) + "\n\n"
    if warning_findings:
        detail += "Warnings:\n" + "\n".join(f"  • {f}" for f in warning_findings) + "\n\n"

    # Build recommended actions based on what was found
    actions = []
    all_lower = " ".join(all_findings).lower()
    if any("open redirect" in f.lower() for f in all_findings):
        actions.append("Validate redirect targets against an explicit allowlist; reject external URLs")
    if any(kw in all_lower for kw in ("phpmyadmin", "adminer", "elasticsearch", "solr")):
        actions.append("Block public access to database admin interfaces using firewall rules or authentication")
    if "actuator" in all_lower:
        actions.append("Restrict Spring Boot Actuator endpoints to internal/private network only")
    if any(kw in all_lower for kw in ("admin panel", "administrator", "wordpress admin", "admin login")):
        actions.append("Require strong multi-factor authentication on all admin interfaces")
    if any(kw in all_lower for kw in ("swagger", "api docs", "openapi", "graphql")):
        actions.append("Restrict API documentation and GraphQL introspection to authenticated users only")
    if "robots.txt" in all_lower:
        actions.append("Remove sensitive paths from robots.txt — this file is public and used by attackers for reconnaissance")
    if any(kw in all_lower for kw in ("directory listing", "uploads directory", "backup directory")):
        actions.append("Disable directory listing in your web server (Apache: Options -Indexes, Nginx: autoindex off)")
    if any(kw in all_lower for kw in ("stack trace", "error page")):
        actions.append("Configure a generic error page in production; disable stack traces and verbose error output")
    if any(kw in all_lower for kw in ("jenkinsfile", "travis", "dockerfile", "docker-compose")):
        actions.append("Remove CI/CD configuration files from web root; do not expose build artifacts publicly")
    if any(kw in all_lower for kw in ("prometheus", "metrics")):
        actions.append("Restrict metrics endpoints to internal monitoring systems only")

    if actions:
        detail += "Recommended Actions:\n" + "\n".join(f"  ✓ {a}" for a in actions)

    if critical_findings:
        return result.critical(
            f"DAST: {len(critical_findings)} critical finding(s) — {critical_findings[0]}",
            detail.strip(),
            impact=30,
        )
    else:
        return result.warn(
            f"DAST: {len(warning_findings)} finding(s) — {warning_findings[0]}",
            detail.strip(),
            impact=12,
        )
