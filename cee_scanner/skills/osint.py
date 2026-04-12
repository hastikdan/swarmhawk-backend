"""
cee_scanner.skills.osint
========================
Agent-Reach–inspired OSINT intelligence checks.

Checks:
  github_poc          – Search GitHub for PoC/exploit repos matching detected tech stack
  contact_discovery   – Discover security contact via security.txt (RFC 9116) + web scan
  threat_feeds        – Match detected software against CISA Known Exploited Vulnerabilities
  github_leaks        – Search GitHub public code for domain credential leaks
"""

import os
import re
import time
import logging

import requests

logger = logging.getLogger("cee_scanner.osint")

TIMEOUT = 10
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# ── CISA KEV in-process cache (6 h TTL) ─────────────────────────────────────
_kev_cache: list = []
_kev_ts: float = 0.0


def _get_kev_catalog() -> list:
    global _kev_cache, _kev_ts
    now = time.time()
    if _kev_cache and (now - _kev_ts) < 21600:
        return _kev_cache
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15,
        )
        if r.status_code == 200:
            _kev_cache = r.json().get("vulnerabilities", [])
            _kev_ts = now
            logger.info(f"KEV catalog loaded: {len(_kev_cache)} entries")
    except Exception as e:
        logger.warning(f"KEV fetch failed: {e}")
    return _kev_cache


def _gh_headers() -> dict:
    h = {"Accept": "application/vnd.github.v3+json"}
    token = os.getenv("GITHUB_TOKEN", "")
    if token:
        h["Authorization"] = f"token {token}"
    return h


def _detect_software_quick(domain: str) -> list:
    """
    Fast HTTP fingerprint — returns [(product, version), ...].
    Shared by check_github_poc and check_threat_feeds.
    """
    software = []
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=8,
            verify=False,
            allow_redirects=True,
            headers=_HEADERS,
        )

        server = resp.headers.get("Server", "").strip()
        if server:
            parts = server.split("/", 1)
            product = parts[0].strip()
            version = parts[1].strip() if len(parts) > 1 else ""
            if product:
                software.append((product, version))

        xpb = resp.headers.get("X-Powered-By", "").strip()
        if xpb:
            parts = xpb.split("/", 1)
            software.append((parts[0].strip(), parts[1].strip() if len(parts) > 1 else ""))

        body = resp.text[:30000]

        wp = re.search(r'wordpress[/\s]+([0-9]+\.[0-9]+[\d.]*)', body, re.I)
        if wp:
            software.append(("WordPress", wp.group(1)))
        elif "/wp-content/" in body or "/wp-includes/" in body:
            software.append(("WordPress", ""))

        if re.search(r'drupal', body, re.I):
            dm = re.search(r'Drupal\s+([0-9]+\.[0-9]+)', body, re.I)
            software.append(("Drupal", dm.group(1) if dm else ""))

        if re.search(r'joomla', body, re.I):
            software.append(("Joomla", ""))

        gen = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{2,80})["\']',
            body, re.I,
        )
        if gen:
            g = gen.group(1)
            parts = g.split(" ", 1)
            if parts[0].lower() not in ("", "none", "html"):
                software.append((parts[0], parts[1] if len(parts) > 1 else ""))

    except Exception as e:
        logger.debug(f"_detect_software_quick: {domain}: {e}")

    # deduplicate by lowercase product name
    seen: set = set()
    unique = []
    for p, v in software:
        key = p.lower()
        if key not in seen:
            seen.add(key)
            unique.append((p, v))
    return unique[:5]


# ── Check 1: GitHub PoC Hunter ───────────────────────────────────────────────

def check_github_poc(domain: str):
    from cee_scanner.checks import CheckResult
    result = CheckResult("github_poc", domain)

    software = _detect_software_quick(domain)
    if not software:
        return result.ok(
            "No software detected — PoC search skipped",
            "Could not fingerprint the tech stack. Run a Tier-2 scan to enable software detection.",
        )

    headers = _gh_headers()
    found_pocs = []

    for product, version in software[:3]:
        query = f"{product} {version} exploit poc".strip() if version else f"{product} exploit poc vulnerability"
        url = (
            "https://api.github.com/search/repositories"
            f"?q={requests.utils.quote(query)}&sort=updated&order=desc&per_page=5"
        )
        try:
            resp = requests.get(url, headers=headers, timeout=12)
            if resp.status_code == 403:
                return result.info(
                    "GitHub rate limited — add GITHUB_TOKEN for PoC scanning",
                    "Set the GITHUB_TOKEN environment variable to remove rate limits.",
                )
            if resp.status_code != 200:
                continue
            for item in resp.json().get("items", [])[:3]:
                updated = item.get("updated_at", "")
                name = item.get("name", "").lower()
                desc = (item.get("description") or "").lower()
                if updated >= "2023-01-01" and any(
                    kw in name + " " + desc for kw in ["poc", "exploit", "rce", "cve", "vuln", "payload", "attack"]
                ):
                    found_pocs.append({
                        "product": product,
                        "version": version,
                        "repo": item["full_name"],
                        "url": item["html_url"],
                        "stars": item.get("stargazers_count", 0),
                        "updated": updated[:10],
                        "desc": (item.get("description") or "")[:120],
                    })
        except Exception as e:
            logger.debug(f"github_poc search failed for {product}: {e}")

    if not found_pocs:
        sw_str = ", ".join(f"{p} {v}".strip() for p, v in software)
        return result.ok(
            "No public PoC exploits found for detected stack",
            f"Checked: {sw_str}",
        )

    # deduplicate repos
    seen_repos: set = set()
    unique_pocs = []
    for poc in found_pocs:
        if poc["repo"] not in seen_repos:
            seen_repos.add(poc["repo"])
            unique_pocs.append(poc)

    detail = "Public exploit/PoC repositories matching detected software:\n\n"
    for poc in unique_pocs[:5]:
        stars = f"  ★{poc['stars']}" if poc["stars"] else ""
        ver = f" {poc['version']}" if poc["version"] else ""
        detail += f"• {poc['product']}{ver}\n  {poc['repo']}{stars}  (updated {poc['updated']})\n"
        if poc["desc"]:
            detail += f"  {poc['desc']}\n"
        detail += "\n"

    if any(p["stars"] > 100 for p in unique_pocs):
        return result.critical(
            f"Weaponised exploit code found for {unique_pocs[0]['product']}",
            detail.strip(),
            impact=15,
        )
    return result.warn(
        f"PoC repos found for detected software ({len(unique_pocs)} repo(s))",
        detail.strip(),
        impact=8,
    )


# ── Check 3: Contact Discovery ───────────────────────────────────────────────

def check_contact_discovery(domain: str):
    from cee_scanner.checks import CheckResult
    result = CheckResult("contact_discovery", domain)

    # 1. RFC 9116 security.txt
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            resp = requests.get(
                f"https://{domain}{path}",
                timeout=8,
                verify=False,
                headers=_HEADERS,
            )
            if resp.status_code == 200 and len(resp.text) < 50000:
                text = resp.text
                contacts = []
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.lower().startswith("contact:"):
                        c = stripped.split(":", 1)[1].strip()
                        if c:
                            contacts.append(c)
                if contacts:
                    has_expires = "expires:" in text.lower()
                    note = "" if has_expires else "\n\nWarning: security.txt is missing an Expires: field (required by RFC 9116)."
                    return result.ok(
                        f"security.txt present — {len(contacts)} contact(s) listed",
                        "Contact:\n" + "\n".join(f"• {c}" for c in contacts) + note,
                    )
        except Exception:
            pass

    # 2. Jina Reader — scan contact/about/security pages for email addresses
    emails_found = []
    for page_path in ["/contact", "/about", "/security", "/"]:
        try:
            jina_url = f"https://r.jina.ai/https://{domain}{page_path}"
            resp = requests.get(
                jina_url,
                timeout=12,
                headers={"Accept": "text/plain", "User-Agent": "SecurityResearch/1.0"},
            )
            if resp.status_code == 200:
                text = resp.text[:6000]
                found = re.findall(r'[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}', text)
                skip_words = {"example", "test", "placeholder", "noreply", "no-reply", "domain", "email"}
                for e in found:
                    e_lower = e.lower()
                    if not any(s in e_lower for s in skip_words):
                        emails_found.append(e)
                if emails_found:
                    break
        except Exception:
            pass

    if emails_found:
        unique = list(dict.fromkeys(emails_found))[:5]
        return result.warn(
            "No security.txt — contact(s) discovered via page scan",
            (
                "RFC 9116 security.txt is missing. Contacts found via website scan:\n"
                + "\n".join(f"• {e}" for e in unique)
                + "\n\nRecommendation: publish /.well-known/security.txt — see https://securitytxt.org"
            ),
            impact=3,
        )

    return result.warn(
        "No security.txt and no public contact discoverable",
        (
            "RFC 9116 security.txt is missing and no security contact was found on the website. "
            "Researchers cannot report vulnerabilities responsibly, increasing incident response time.\n\n"
            "Recommendation: publish /.well-known/security.txt with Contact: and Expires: fields."
        ),
        impact=5,
    )


# ── Check 4: CISA KEV Threat Feed ────────────────────────────────────────────

def check_threat_feeds(domain: str):
    from cee_scanner.checks import CheckResult
    result = CheckResult("threat_feeds", domain)

    kev = _get_kev_catalog()
    if not kev:
        return result.info(
            "CISA KEV feed unavailable — check skipped",
            "Could not fetch the CISA Known Exploited Vulnerabilities catalog.",
        )

    software = _detect_software_quick(domain)
    if not software:
        return result.ok(
            "No software detected — KEV matching skipped",
            f"CISA KEV has {len(kev)} entries. Tier-2 scan required to detect software for matching.",
        )

    software_lower = [(p.lower(), v) for p, v in software]
    matched = []

    for entry in kev:
        vendor  = entry.get("vendorProject", "").lower()
        product = entry.get("product", "").lower()
        for prod_l, _ in software_lower:
            if prod_l in vendor or prod_l in product or vendor in prod_l or product in prod_l:
                if not any(m["cve"] == entry.get("cveID") for m in matched):
                    matched.append({
                        "cve":        entry.get("cveID", ""),
                        "product":    entry.get("product", ""),
                        "vendor":     entry.get("vendorProject", ""),
                        "desc":       entry.get("shortDescription", "")[:160],
                        "due_date":   entry.get("dueDate", ""),
                        "ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
                    })

    if not matched:
        sw_str = ", ".join(f"{p} {v}".strip() for p, v in software)
        return result.ok(
            "No CISA KEV matches for detected software",
            f"Checked {len(software)} component(s) against {len(kev)} CISA KEV entries.\nStack: {sw_str}",
        )

    matched.sort(key=lambda x: (0 if x["ransomware"] == "Known" else 1, x["cve"]))
    has_ransomware = any(m["ransomware"] == "Known" for m in matched)

    detail = f"CISA Known Exploited Vulnerabilities matching your tech stack:\n\n"
    for m in matched[:6]:
        rw = "  ⚠ RANSOMWARE CAMPAIGNS ACTIVE" if m["ransomware"] == "Known" else ""
        detail += f"• {m['cve']} — {m['vendor']} {m['product']}{rw}\n"
        if m["desc"]:
            detail += f"  {m['desc']}\n"
        if m["due_date"]:
            detail += f"  CISA remediation deadline: {m['due_date']}\n"
        detail += "\n"
    if len(matched) > 6:
        detail += f"...and {len(matched) - 6} more match(es)."

    if has_ransomware or len(matched) >= 3:
        return result.critical(
            f"{len(matched)} CISA KEV match(es) — active exploitation confirmed",
            detail.strip(),
            impact=18,
        )
    return result.warn(
        f"{len(matched)} CISA KEV match(es) for detected software",
        detail.strip(),
        impact=10,
    )


# ── Check 6: GitHub Credential Leak Scan ─────────────────────────────────────

def check_github_leaks(domain: str):
    from cee_scanner.checks import CheckResult
    result = CheckResult("github_leaks", domain)

    headers = _gh_headers()
    query = f'"{domain}" password OR secret OR api_key OR token OR credential'
    url = (
        "https://api.github.com/search/code"
        f"?q={requests.utils.quote(query)}&per_page=10"
    )

    try:
        resp = requests.get(url, headers=headers, timeout=12)

        if resp.status_code == 403:
            return result.info(
                "GitHub rate limited — add GITHUB_TOKEN for leak scanning",
                "Set the GITHUB_TOKEN environment variable to remove rate limits.",
            )
        if resp.status_code == 422:
            return result.ok(
                "No credential leaks found on GitHub",
                f"No public files reference {domain} with credential keywords.",
            )
        if resp.status_code != 200:
            return result.error(
                "GitHub credential scan failed",
                f"HTTP {resp.status_code}",
            )

        data  = resp.json()
        items = data.get("items", [])
        total = data.get("total_count", 0)

        if not items:
            return result.ok(
                "No credential leaks found on GitHub",
                f"Searched public GitHub code — no files contain '{domain}' with credential keywords.",
            )

        detail = (
            f"Found {total} public GitHub file(s) containing '{domain}' "
            f"alongside credential keywords (password, secret, api_key, token):\n\n"
        )
        for item in items[:6]:
            repo  = item.get("repository", {}).get("full_name", "unknown/unknown")
            fname = item.get("name", "")
            furl  = item.get("html_url", "")
            detail += f"• {repo} / {fname}\n  {furl}\n"
        if total > 6:
            detail += f"\n...and {total - 6} more file(s)."

        if total >= 5:
            return result.critical(
                f"{total} public GitHub files may expose credentials for {domain}",
                detail.strip(),
                impact=20,
            )
        return result.warn(
            f"{total} GitHub file(s) reference {domain} with credential keywords",
            detail.strip(),
            impact=12,
        )

    except Exception as e:
        return result.error("GitHub credential scan failed", str(e)[:120])
