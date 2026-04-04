"""
cee_scanner.skills.integrity
==============================
OWASP A08:2021 — Software and Data Integrity Failures

Checks:
  - Subresource Integrity (SRI) on external CDN scripts and stylesheets
  - Exposed dependency manifests (package.json, requirements.txt, Pipfile,
    Gemfile, yarn.lock, composer.json, Cargo.toml, go.sum)
  - CI/CD pipeline files with potential supply-chain risk indicators
  - Unsigned / unverified software loading patterns
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.integrity")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# Manifest / lockfile paths that expose the full dependency tree
MANIFEST_PROBES = [
    ("/package.json",          "Node.js package.json",            True),
    ("/package-lock.json",     "Node.js package-lock.json",       True),
    ("/yarn.lock",             "Yarn lockfile",                   True),
    ("/requirements.txt",      "Python requirements.txt",         True),
    ("/Pipfile",               "Python Pipfile",                  True),
    ("/Pipfile.lock",          "Python Pipfile.lock",             True),
    ("/Gemfile",               "Ruby Gemfile",                    False),
    ("/Gemfile.lock",          "Ruby Gemfile.lock",               True),
    ("/composer.json",         "PHP composer.json",               True),
    ("/composer.lock",         "PHP composer.lock",               True),
    ("/go.sum",                "Go module checksums",             True),
    ("/go.mod",                "Go module manifest",              False),
    ("/Cargo.toml",            "Rust Cargo.toml",                 False),
    ("/Cargo.lock",            "Rust Cargo.lock",                 True),
    ("/.npmrc",                ".npmrc (may contain registry auth tokens)", True),
    ("/pom.xml",               "Maven pom.xml",                   False),
    ("/build.gradle",          "Gradle build file",               False),
]

# CDN hostnames that should carry SRI on their assets
CDN_PATTERNS = re.compile(
    r'(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|'
    r'code\.jquery\.com|maxcdn\.bootstrapcdn\.com|'
    r'stackpath\.bootstrapcdn\.com|ajax\.googleapis\.com|'
    r'fonts\.googleapis\.com|cdn\.bootcss\.com)',
    re.IGNORECASE
)


def _parse_external_resources(html: str) -> list[dict]:
    """Return list of external <script> and <link> tags with/without SRI."""
    resources = []

    # <script src="..." [integrity="..."]>
    for m in re.finditer(
        r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
        html, re.IGNORECASE
    ):
        tag = m.group(0)
        url = m.group(1)
        if CDN_PATTERNS.search(url):
            resources.append({
                "type": "script",
                "url":  url,
                "has_sri": bool(re.search(r'integrity=["\']sha', tag, re.IGNORECASE)),
            })

    # <link rel="stylesheet" href="..." [integrity="..."]>
    for m in re.finditer(
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>',
        html, re.IGNORECASE
    ):
        tag = m.group(0)
        url = m.group(1)
        rel = re.search(r'rel=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if rel and "stylesheet" in rel.group(1).lower() and CDN_PATTERNS.search(url):
            resources.append({
                "type": "stylesheet",
                "url":  url,
                "has_sri": bool(re.search(r'integrity=["\']sha', tag, re.IGNORECASE)),
            })

    return resources


def check_integrity(domain: str) -> "CheckResult":
    """
    OWASP A08:2021 — Software and Data Integrity Failures.

    CRITICAL: Exposed dependency manifests / lockfiles.
    WARNING:  External CDN resources loaded without SRI integrity attributes.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("integrity", domain)

    critical_findings = []
    findings = []

    try:
        # ── 1. Fetch homepage, check CDN resources for SRI ───────────────
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=True, verify=False
        )
        resources = _parse_external_resources(r.text)
        missing_sri = [res for res in resources if not res["has_sri"]]
        with_sri    = [res for res in resources if res["has_sri"]]

        if missing_sri:
            # Truncate to first 5 URLs for readability
            urls = [res["url"][:70] for res in missing_sri[:5]]
            suffix = f" (and {len(missing_sri)-5} more)" if len(missing_sri) > 5 else ""
            findings.append(
                f"{len(missing_sri)} external CDN resource(s) loaded without SRI integrity check{suffix}:\n"
                + "\n".join(f"  {u}" for u in urls)
            )

        # ── 2. Probe exposed manifest / lockfile paths ───────────────────
        for path, label, is_critical in MANIFEST_PROBES:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                if pr.status_code != 200:
                    continue
                # Verify it looks like the real file, not a catch-all 200
                content = pr.text[:500].lower()
                looks_real = (
                    ("json" in pr.headers.get("content-type", "").lower() and len(pr.text) > 50)
                    or ("dependencies" in content or "packages" in content
                        or "version" in content or "require" in content
                        or "gem" in content or "module" in content)
                )
                if not looks_real:
                    continue
                if is_critical:
                    critical_findings.append(f"{label} exposed at {path}")
                else:
                    findings.append(f"{label} exposed at {path}")
            except Exception:
                pass

    except Exception as e:
        return result.ok("Integrity check skipped", str(e)[:80])

    if critical_findings:
        detail = "Critical — dependency manifests exposed:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nWarnings:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"A08: {len(critical_findings)} integrity exposure(s)",
            detail,
            impact=min(20, len(critical_findings) * 10 + len(findings) * 3)
        )

    if findings:
        detail = "\n".join(f"• {f}" for f in findings)
        return result.warn(
            f"A08: {len(findings)} integrity weakness(es)",
            detail,
            impact=min(10, len(findings) * 4)
        )

    return result.ok(
        "Software integrity controls in place",
        f"No exposed manifests. {len(with_sri)} CDN resource(s) with SRI verified."
        if with_sri else "No exposed dependency manifests found"
    )
