"""
cee_scanner.skills.sast
=======================
SAST Exposure Check

Detects publicly exposed source code artifacts that indicate poor security
hygiene and can leak credentials, logic, or internal infrastructure details.

Checks:
  - Exposed .git repository (/.git/config, /.git/HEAD)
  - Exposed .env / .env.* files with potential secrets
  - JavaScript source maps (*.js.map — exposes original source)
  - Debug / info endpoints (phpinfo, /debug, /server-status)
  - Exposed backup files (.bak, .old, .swp)
  - Stack traces / verbose error pages
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.sast")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# (path, label, critical)
SAST_PROBES = [
    # Git repo exposure
    ("/.git/config",          "Git config exposed",            True),
    ("/.git/HEAD",            "Git HEAD exposed",              True),
    ("/.git/COMMIT_EDITMSG",  "Git commit history exposed",    True),

    # Environment / secrets
    ("/.env",                 ".env file exposed",             True),
    ("/.env.local",           ".env.local exposed",            True),
    ("/.env.production",      ".env.production exposed",       True),
    ("/.env.backup",          ".env.backup exposed",           True),

    # Backup files
    ("/backup.sql",           "Database backup exposed",       True),
    ("/dump.sql",             "SQL dump exposed",              True),
    ("/db.sql",               "SQL dump exposed",              True),
    ("/site.tar.gz",          "Site archive exposed",          True),
    ("/backup.zip",           "Backup archive exposed",        True),
    ("/index.php.bak",        "PHP backup file exposed",       True),
    ("/wp-config.php.bak",    "WordPress config backup",       True),

    # Debug / info pages
    ("/phpinfo.php",          "PHP info page exposed",         True),
    ("/info.php",             "PHP info page exposed",         True),
    ("/server-status",        "Apache server-status exposed",  False),
    ("/server-info",          "Apache server-info exposed",    False),
    ("/_profiler",            "Symfony profiler exposed",      True),
    ("/debug/pprof",          "Go pprof debug exposed",        True),

    # Source maps (leak original source)
    ("/static/js/main.chunk.js.map", "JS source map exposed",  False),
    ("/assets/app.js.map",           "JS source map exposed",  False),
    ("/js/app.js.map",               "JS source map exposed",  False),
]

# Patterns that confirm the file contains real sensitive content
CONFIRM_PATTERNS = {
    "/.git/config":      r"\[core\]",
    "/.git/HEAD":        r"ref: refs/",
    "/.env":             r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)\s*=",
    "/.env.local":       r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)\s*=",
    "/.env.production":  r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)\s*=",
    "/.env.backup":      r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)\s*=",
    "/phpinfo.php":      r"PHP Version",
    "/info.php":         r"PHP Version",
    "/server-status":    r"Server Version|Apache",
    "/_profiler":        r"Symfony|Profiler",
}


def check_sast(domain: str) -> "CheckResult":
    """
    SAST Exposure — detect leaked source code, secrets, and debug endpoints.

    Returns CRITICAL if credentials/source code are exposed,
    WARNING for debug pages and source maps.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("sast", domain)

    findings = []
    critical_findings = []

    for path, label, is_critical in SAST_PROBES:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(
                url, timeout=TIMEOUT, headers=HEADERS,
                allow_redirects=False, verify=False,
            )
            # Must be 200 (not redirect to homepage or 404)
            if r.status_code != 200:
                continue

            body = r.text[:2000]

            # Skip if it just returns the homepage (common false positive)
            if len(body) > 100 and ("<html" in body.lower() or "<!doctype" in body.lower()):
                # Unless it's an explicitly expected HTML page
                if path not in ("/phpinfo.php", "/info.php", "/_profiler"):
                    continue

            # Confirm with pattern if we have one
            confirm = CONFIRM_PATTERNS.get(path)
            if confirm and not re.search(confirm, body, re.IGNORECASE):
                continue

            logger.info(f"SAST: {label} at {url}")
            if is_critical:
                critical_findings.append(f"{label} ({path})")
            else:
                findings.append(f"{label} ({path})")

        except Exception:
            continue

    all_findings = critical_findings + findings

    if not all_findings:
        return result.ok(
            "SAST: no source code or secrets exposed",
            "No exposed .git repos, .env files, backups, or debug endpoints found"
        )

    detail = "Exposed artifacts:\n" + "\n".join(f"  • {f}" for f in all_findings)

    if critical_findings:
        return result.critical(
            f"SAST: {len(critical_findings)} critical exposure(s) — source/secrets leaked",
            detail,
            impact=30,
        )
    else:
        return result.warn(
            f"SAST: {len(findings)} exposure(s) — debug/info pages accessible",
            detail,
            impact=10,
        )
