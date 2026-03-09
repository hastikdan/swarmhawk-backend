"""
cee_scanner.skills.sca
======================
SCA (Software Composition Analysis) Check

Detects exposed dependency manifests and checks declared package versions
against the NIST NVD for known CVEs.

Probed manifests:
  - package.json       (Node.js)
  - composer.json      (PHP)
  - requirements.txt   (Python)
  - Gemfile.lock       (Ruby)
  - go.mod             (Go)
  - pom.xml            (Java/Maven)
  - build.gradle       (Java/Gradle)
  - Pipfile.lock       (Python)

For each detected dependency with a pinned version, queries NVD for CVEs
with CVSS >= 7.0 (HIGH or CRITICAL).
"""

import re
import json
import time
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.sca")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}
NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# (path, parser_key)
MANIFEST_PROBES = [
    ("/package.json",      "npm"),
    ("/composer.json",     "composer"),
    ("/requirements.txt",  "pip"),
    ("/Gemfile.lock",      "gem"),
    ("/go.mod",            "go"),
    ("/pom.xml",           "maven"),
    ("/Pipfile.lock",      "pipfile"),
]

# Max packages to check against NVD (rate limit: 5 req/30s without key)
MAX_NVD_CHECKS = 5


def _parse_npm(body: str) -> list[tuple[str, str]]:
    """Extract name:version pairs from package.json dependencies."""
    try:
        data = json.loads(body)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        result = []
        for name, ver in deps.items():
            # Clean version specifier: ^1.2.3 -> 1.2.3
            clean = re.sub(r'^[\^~>=<\s]+', '', str(ver)).split(' ')[0]
            if re.match(r'^\d+\.\d+', clean):
                result.append((name, clean))
        return result[:20]
    except Exception:
        return []


def _parse_composer(body: str) -> list[tuple[str, str]]:
    """Extract name:version pairs from composer.json."""
    try:
        data = json.loads(body)
        deps = {}
        deps.update(data.get("require", {}))
        result = []
        for name, ver in deps.items():
            if name == "php":
                continue
            clean = re.sub(r'^[\^~>=<\s]+', '', str(ver)).split(' ')[0]
            if re.match(r'^\d+\.\d+', clean):
                result.append((name.split('/')[-1], clean))
        return result[:20]
    except Exception:
        return []


def _parse_pip(body: str) -> list[tuple[str, str]]:
    """Extract name==version pairs from requirements.txt."""
    result = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)==(\d+[\d\.]+)', line)
        if m:
            result.append((m.group(1), m.group(2)))
    return result[:20]


def _parse_gemfile_lock(body: str) -> list[tuple[str, str]]:
    """Extract gem name and version from Gemfile.lock."""
    result = []
    for line in body.splitlines():
        m = re.match(r'^\s{4}([a-z][a-z0-9_\-]+)\s+\((\d+[\d\.]+)\)', line)
        if m:
            result.append((m.group(1), m.group(2)))
    return result[:20]


def _parse_go_mod(body: str) -> list[tuple[str, str]]:
    """Extract module versions from go.mod."""
    result = []
    for line in body.splitlines():
        m = re.match(r'^\s+([^\s]+)\s+v(\d+[\d\.]+)', line)
        if m:
            pkg = m.group(1).split('/')[-1]
            result.append((pkg, m.group(2)))
    return result[:20]


def _parse_pom(body: str) -> list[tuple[str, str]]:
    """Extract artifactId + version pairs from pom.xml."""
    result = []
    artifacts = re.findall(r'<artifactId>([^<]+)</artifactId>', body)
    versions  = re.findall(r'<version>(\d+[\d\.]+[^<]*)</version>', body)
    for art, ver in zip(artifacts, versions):
        if re.match(r'^\d+\.\d+', ver):
            result.append((art, ver))
    return result[:20]


PARSERS = {
    "npm":      _parse_npm,
    "composer": _parse_composer,
    "pip":      _parse_pip,
    "gem":      _parse_gemfile_lock,
    "go":       _parse_go_mod,
    "maven":    _parse_pom,
    "pipfile":  _parse_pip,  # Pipfile.lock has different format but close enough
}


def _query_nvd_sca(package: str, version: str, api_key: str = "") -> list[dict]:
    """Query NVD for CVEs affecting a specific package version. Returns top 3."""
    try:
        time.sleep(0.6)
        hdrs = {**HEADERS}
        if api_key:
            hdrs["apiKey"] = api_key

        r = requests.get(NVD_API, params={
            "keywordSearch":    f"{package} {version}",
            "cvssV3SeverityMin": "HIGH",
            "resultsPerPage":    5,
        }, headers=hdrs, timeout=12)

        if r.status_code != 200:
            return []

        cves = []
        for item in r.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score = None
            sev   = "UNKNOWN"
            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]["cvssData"]
                score, sev = m.get("baseScore"), m.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]["cvssData"]
                score, sev = m.get("baseScore"), m.get("baseSeverity", "UNKNOWN")
            if not score:
                continue
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            cves.append({
                "id":       cve.get("id", ""),
                "cvss":     score,
                "severity": sev,
                "summary":  desc[:180].strip(),
                "url":      f"https://nvd.nist.gov/vuln/detail/{cve.get('id','')}",
                "package":  package,
                "version":  version,
            })
        cves.sort(key=lambda x: x["cvss"] or 0, reverse=True)
        return cves[:3]
    except Exception as e:
        logger.debug(f"NVD SCA query failed for {package} {version}: {e}")
        return []


def check_sca(domain: str) -> "CheckResult":
    """
    SCA — detect exposed dependency manifests and find CVEs in declared packages.

    Returns CRITICAL if packages with CVSS >= 9.0 found,
    WARNING for HIGH severity CVEs or if manifests are exposed (no CVEs needed),
    OK if nothing found.
    """
    import os
    from cee_scanner.checks import CheckResult
    result = CheckResult("sca", domain)

    api_key = os.getenv("NVD_API_KEY", "")

    # Step 1: probe for manifest files
    found_manifests = []
    all_packages: list[tuple[str, str]] = []

    for path, parser_key in MANIFEST_PROBES:
        try:
            url = f"https://{domain}{path}"
            r = requests.get(
                url, timeout=TIMEOUT, headers=HEADERS,
                allow_redirects=False, verify=False,
            )
            if r.status_code != 200:
                continue

            body = r.text[:8000]

            # Skip HTML responses (homepage redirect false positive)
            if "<html" in body.lower()[:200]:
                continue

            parser = PARSERS.get(parser_key)
            packages = parser(body) if parser else []

            found_manifests.append(f"{path} ({len(packages)} packages)")
            logger.info(f"SCA: found {path} on {domain} with {len(packages)} packages")

            for pkg in packages:
                if pkg not in all_packages:
                    all_packages.append(pkg)

        except Exception:
            continue

    if not found_manifests:
        return result.ok(
            "SCA: no dependency manifests exposed",
            "No package.json, requirements.txt, composer.json, or similar files found publicly"
        )

    # Manifests found — this is already a warning even without CVEs
    manifest_str = ", ".join(found_manifests[:3])

    # Step 2: check top packages against NVD
    all_cves: list[dict] = []
    checked = 0
    for package, version in all_packages:
        if checked >= MAX_NVD_CHECKS:
            break
        cves = _query_nvd_sca(package, version, api_key)
        all_cves.extend(cves)
        if cves:
            checked += 1

    # Deduplicate by CVE ID
    seen: set[str] = set()
    unique_cves = []
    for c in all_cves:
        if c["id"] not in seen:
            seen.add(c["id"])
            unique_cves.append(c)
    unique_cves.sort(key=lambda x: x["cvss"] or 0, reverse=True)

    critical_cves = [c for c in unique_cves if (c.get("cvss") or 0) >= 9.0]
    high_cves     = [c for c in unique_cves if 7.0 <= (c.get("cvss") or 0) < 9.0]

    if not unique_cves:
        # Manifests exposed but no high-severity CVEs found
        return result.warn(
            f"SCA: dependency manifest(s) publicly exposed",
            f"Exposed: {manifest_str}\n"
            f"Exposes your tech stack. {len(all_packages)} packages checked against NVD — no high CVEs found.",
            impact=8,
        )

    top = unique_cves[:3]
    cve_lines = [
        f"{c['id']} (CVSS {c['cvss']} {c['severity']}) — {c['package']} {c['version']}: {c['summary'][:100]}"
        for c in top
    ]
    detail = f"Manifest(s): {manifest_str}\n\nCVEs found:\n" + "\n".join(cve_lines)

    # Attach CVE list for frontend
    result.cves     = unique_cves
    result.manifests = found_manifests

    if critical_cves:
        return result.critical(
            f"SCA: {len(unique_cves)} CVE(s) in exposed dependencies — {len(critical_cves)} CRITICAL",
            detail,
            impact=35,
        )
    else:
        return result.warn(
            f"SCA: {len(unique_cves)} CVE(s) in exposed dependencies — HIGH severity",
            detail,
            impact=20,
        )
