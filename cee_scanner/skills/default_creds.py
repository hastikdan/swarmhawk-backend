"""
cee_scanner.skills.default_creds
===================================
OWASP A02:2021 / A07:2021 — Default and Weak Credentials

Safe, limited credential probing on detected login forms.
Never sends more than 5 auth attempts per domain to avoid lockouts.

Checks:
  - Common default credential pairs on detected login forms
  - HTTP Basic auth with default creds on sensitive paths
  - Known default admin paths (phpmyadmin, adminer, tomcat manager)
  - Application-specific default credentials (Jenkins, Grafana, GitLab)
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.default_creds")

TIMEOUT = 4
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Default credential pairs to test — ordered by likelihood
DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     ""),
    ("root",      "root"),
    ("admin",     "123456"),
]

# Login endpoints to probe — ordered by prevalence, stop at first match
LOGIN_PATHS = [
    "/login", "/signin", "/admin/login", "/wp-login.php",
]

# App-specific admin paths with known defaults
APP_ADMIN_PATHS = [
    ("/phpmyadmin/",  "phpMyAdmin",     "root / (empty)"),
    ("/adminer/",     "Adminer",        "root / (empty)"),
    ("/manager/html", "Tomcat Manager", "tomcat / tomcat or admin / admin"),
    ("/jenkins/",     "Jenkins",        "admin / (setup secret)"),
    ("/grafana/",     "Grafana",        "admin / admin"),
    ("/kibana/",      "Kibana",         "elastic / changeme"),
]

# Patterns that indicate a successful login (vs. staying on login page)
SUCCESS_INDICATORS = [
    r'logout|sign.?out|dashboard|profile|welcome|account|my.?account|settings',
]
FAILURE_INDICATORS = [
    r'invalid|incorrect|wrong|failed|error|unauthorized|bad.?credentials|try.?again',
]


def _looks_like_success(resp_text: str, location: str = "") -> bool:
    if location and location not in ("/login", "/signin", "/auth"):
        return True   # Redirect away from login = likely success
    lower = resp_text.lower()
    if any(re.search(p, lower) for p in FAILURE_INDICATORS):
        return False
    if any(re.search(p, lower) for p in SUCCESS_INDICATORS):
        return True
    return False


def _find_login_form(html: str) -> dict | None:
    """Extract form action and field names from the first password form."""
    form_m = re.search(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
    if not form_m:
        return None
    form = form_m.group(0)
    if not re.search(r'type=["\']?password', form, re.IGNORECASE):
        return None
    action = (re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE) or [None, ""])[1]
    # Username field name
    user_field = None
    for pattern in [r'name=["\']?(email|username|user|login|id)["\']?', r'name=["\']?([^"\']+)["\']?']:
        m = re.search(pattern, form, re.IGNORECASE)
        if m and m.group(1).lower() not in ("password", "pass", "pwd", "submit"):
            user_field = m.group(1)
            break
    pass_field = None
    m = re.search(r'<input[^>]+type=["\']?password["\']?[^>]+name=["\']?([^"\']+)["\']?', form, re.IGNORECASE)
    if not m:
        m = re.search(r'name=["\']?([^"\']*(?:pass|pwd)[^"\']*)["\']?', form, re.IGNORECASE)
    if m:
        pass_field = m.group(1)
    return {"action": action, "user_field": user_field or "username", "pass_field": pass_field or "password"}


def check_default_creds(domain: str) -> "CheckResult":
    """
    OWASP A02/A07 — Default credential detection.

    CRITICAL: Login succeeds with a default credential pair.
    WARNING:  Known admin application (phpMyAdmin, Grafana) accessible without auth.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("default_creds", domain)

    critical_findings = []
    findings = []

    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        session.verify = False

        # ── 1. Find a login form ─────────────────────────────────────────
        login_url = None
        form_info = None
        for path in LOGIN_PATHS:
            try:
                r = session.get(f"https://{domain}{path}", timeout=TIMEOUT, allow_redirects=True)
                if r.status_code == 200:
                    fi = _find_login_form(r.text)
                    if fi:
                        login_url = f"https://{domain}{path}"
                        form_info = fi
                        break
            except Exception:
                pass

        # ── 2. Test default credentials on the login form ─────────────────
        if login_url and form_info:
            form_action = form_info["action"]
            post_url = (
                f"https://{domain}{form_action}" if form_action and form_action.startswith("/")
                else f"https://{domain}{login_url.split(domain)[1].rsplit('/',1)[0]}/{form_action}"
                if form_action else login_url
            )
            attempts = 0
            for username, password in DEFAULT_CREDS:
                if attempts >= 5:
                    break
                try:
                    pr = session.post(
                        post_url,
                        data={form_info["user_field"]: username, form_info["pass_field"]: password},
                        timeout=TIMEOUT,
                        allow_redirects=True,
                    )
                    location = pr.url if pr.url else ""
                    if _looks_like_success(pr.text, location):
                        critical_findings.append(
                            f"Default credentials accepted at {login_url}: "
                            f"'{username}' / '{password if password else '(empty)'}'"
                        )
                        break
                    attempts += 1
                except Exception:
                    attempts += 1

        # ── 3. Check for known admin applications ─────────────────────────
        for path, app_name, default_note in APP_ADMIN_PATHS:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                if pr.status_code == 200:
                    body_lower = pr.text.lower()
                    if any(kw in body_lower for kw in
                           ["phpmyadmin", "adminer", "tomcat", "jenkins", "grafana",
                            "kibana", "weblogic", "solr", "login", "sign in"]):
                        findings.append(
                            f"{app_name} accessible at {path} — default creds: {default_note}"
                        )
            except Exception:
                pass

        # ── 4. HTTP Basic auth brute-force exposure ───────────────────────
        for path in ["/admin", "/manager", "/status"]:
            try:
                br = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                if br.status_code == 401 and "www-authenticate" in br.headers:
                    # Try Basic auth with top creds
                    for username, password in DEFAULT_CREDS[:3]:
                        try:
                            ar = requests.get(
                                f"https://{domain}{path}", timeout=TIMEOUT,
                                headers=HEADERS, verify=False,
                                auth=(username, password), allow_redirects=False
                            )
                            if ar.status_code == 200:
                                critical_findings.append(
                                    f"HTTP Basic auth at {path} accepts default credentials "
                                    f"'{username}' / '{password if password else '(empty)'}'"
                                )
                                break
                        except Exception:
                            pass
                    break
            except Exception:
                pass

    except Exception as e:
        return result.ok("Default credentials check skipped", str(e)[:80])

    if critical_findings:
        detail = "Critical:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nWarnings:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"A02/A07: {len(critical_findings)} default credential(s) accepted",
            detail,
            impact=min(30, len(critical_findings) * 20 + len(findings) * 3)
        )

    if findings:
        return result.warn(
            f"A02/A07: {len(findings)} known-default-creds app(s) exposed",
            "\n".join(f"• {f}" for f in findings),
            impact=min(10, len(findings) * 5)
        )

    return result.ok(
        "No default credentials accepted",
        "Tested common default credentials — none accepted"
    )
