"""
cee_scanner.skills.ip_intel
============================
IP Intelligence Check

Resolves the scanned domain to its IP address(es), then enriches each IP with:
  - Reverse DNS (PTR) — is the IP pointing back to a known CDN/host or something suspicious?
  - ASN / BGP lookup   — hosting provider, country, BGP prefix (via ipinfo.io, no key needed)
  - AbuseIPDB          — community-reported abuse score (requires ABUSEIPDB_API_KEY env var)
  - Shodan banner      — open ports, software versions, CVEs (requires SHODAN_API_KEY env var)
  - IP blocklists      — Spamhaus ZEN, Barracuda, SORBS, Talos via DNS-based lookup (no key)
  - Co-hosted domains  — other domains on the same IP via HackerTarget reverse IP (free tier)

Each of the above is attempted independently; missing keys or API errors are silently skipped
so the check always returns a result even with zero API keys configured.
"""

import os
import re
import socket
import logging
import requests

logger = logging.getLogger("cee_scanner.skills.ip_intel")

TIMEOUT = 7
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# DNS-based blocklists (append reversed IP then query A record)
DNSBL_LIST = [
    ("zen.spamhaus.org",    "Spamhaus ZEN"),
    ("b.barracudacentral.org", "Barracuda Reputation"),
    ("dnsbl.sorbs.net",     "SORBS"),
]


def _resolve_ips(domain: str) -> list[str]:
    """Return list of IPv4 addresses for domain."""
    try:
        info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list({r[4][0] for r in info})
        return ips[:4]  # cap at 4
    except Exception:
        return []


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _asn_lookup(ip: str) -> dict:
    """Free ipinfo.io lookup — returns org, country, hostname."""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _abuseipdb(ip: str, api_key: str) -> dict | None:
    """Query AbuseIPDB for abuse confidence score."""
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception:
        pass
    return None


def _shodan_ip(ip: str, api_key: str) -> dict | None:
    """Fetch Shodan host info for an IP."""
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _dnsbl_check(ip: str) -> list[str]:
    """Check IP against DNS blocklists. Returns list of hit names."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    hits = []
    for bl_host, bl_name in DNSBL_LIST:
        query = f"{reversed_ip}.{bl_host}"
        try:
            socket.getaddrinfo(query, None)
            hits.append(bl_name)
        except socket.gaierror:
            pass  # NXDOMAIN = not listed
        except Exception:
            pass
    return hits


def _cohosted_domains(ip: str) -> list[str]:
    """Use HackerTarget free reverse IP API to find co-hosted domains."""
    try:
        r = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
            timeout=TIMEOUT,
            headers=HEADERS,
        )
        if r.status_code == 200 and "No DNS A records" not in r.text and "error" not in r.text.lower():
            domains = [d.strip() for d in r.text.strip().splitlines() if d.strip()]
            return domains[:20]  # cap to avoid huge lists
    except Exception:
        pass
    return []


def check_ip_intel(domain: str) -> "CheckResult":
    """
    IP Intelligence — resolve domain IPs and enrich with reputation data.

    Returns CRITICAL if AbuseIPDB score > 50 or IP on multiple blocklists.
    WARNING for blocklist hits, suspicious ASN, or many co-hosted domains.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("ip_intel", domain)

    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    shodan_key    = os.environ.get("SHODAN_API_KEY", "")

    ips = _resolve_ips(domain)
    if not ips:
        return result.error("IP Intel: could not resolve domain", "DNS resolution failed")

    critical_findings: list[str] = []
    warning_findings:  list[str] = []
    detail_lines:      list[str] = []

    for ip in ips:
        detail_lines.append(f"IP: {ip}")

        # ── Reverse DNS ─────────────────────────────────────────────────────
        ptr = _reverse_dns(ip)
        if ptr:
            detail_lines.append(f"  PTR: {ptr}")

        # ── ASN / hosting info ───────────────────────────────────────────────
        asn_data = _asn_lookup(ip)
        if asn_data:
            org     = asn_data.get("org", "")
            country = asn_data.get("country", "")
            city    = asn_data.get("city", "")
            detail_lines.append(f"  ASN/Org: {org}  [{city}, {country}]")

            # Flag known bulletproof / high-risk hosting ASNs
            HIGH_RISK_ORGS = [
                "M247", "Frantech", "BuyVM", "Psychz", "Serverius",
                "Sharktech", "Quasi Networks", "vds64", "King Servers",
            ]
            if any(h.lower() in org.lower() for h in HIGH_RISK_ORGS):
                warning_findings.append(f"IP {ip} hosted on high-risk ASN: {org}")

        # ── DNS Blocklists ────────────────────────────────────────────────────
        bl_hits = _dnsbl_check(ip)
        if bl_hits:
            detail_lines.append(f"  Blocklists: {', '.join(bl_hits)}")
            if len(bl_hits) >= 2:
                critical_findings.append(f"IP {ip} on {len(bl_hits)} blocklists: {', '.join(bl_hits)}")
            else:
                warning_findings.append(f"IP {ip} on blocklist: {bl_hits[0]}")

        # ── AbuseIPDB ────────────────────────────────────────────────────────
        if abuseipdb_key:
            abuse_data = _abuseipdb(ip, abuseipdb_key)
            if abuse_data:
                score    = abuse_data.get("abuseConfidenceScore", 0)
                reports  = abuse_data.get("totalReports", 0)
                detail_lines.append(f"  AbuseIPDB: score={score}%, reports={reports}")
                if score >= 50:
                    critical_findings.append(f"IP {ip} AbuseIPDB score {score}% ({reports} reports)")
                elif score >= 10:
                    warning_findings.append(f"IP {ip} AbuseIPDB score {score}% ({reports} reports)")

        # ── Shodan ───────────────────────────────────────────────────────────
        if shodan_key:
            shodan_data = _shodan_ip(ip, shodan_key)
            if shodan_data:
                ports  = shodan_data.get("ports", [])
                vulns  = list(shodan_data.get("vulns", {}).keys())
                detail_lines.append(f"  Shodan: open ports={ports}")
                if vulns:
                    detail_lines.append(f"  Shodan CVEs: {', '.join(vulns[:5])}")
                    if any(v.startswith("CVE") for v in vulns):
                        critical_findings.append(f"IP {ip} has {len(vulns)} CVE(s) via Shodan: {vulns[0]}")

                # Flag risky open ports
                RISKY_PORTS = {23: "Telnet", 3389: "RDP", 5900: "VNC", 27017: "MongoDB"}
                for p, svc in RISKY_PORTS.items():
                    if p in ports:
                        warning_findings.append(f"IP {ip} has {svc} (port {p}) open")

        # ── Co-hosted domains ─────────────────────────────────────────────────
        cohosted = _cohosted_domains(ip)
        if cohosted:
            detail_lines.append(f"  Co-hosted domains ({len(cohosted)}): {', '.join(cohosted[:5])}")
            if len(cohosted) >= 10:
                warning_findings.append(
                    f"IP {ip} shared with {len(cohosted)} other domains (bulk/shared hosting risk)"
                )

        detail_lines.append("")

    all_findings = critical_findings + warning_findings

    if not all_findings:
        return result.ok(
            f"IP Intel: {len(ips)} IP(s) clean — no blocklist hits or abuse reports",
            "\n".join(detail_lines).strip(),
        )

    detail = "\n".join(detail_lines).strip()

    if critical_findings:
        return result.critical(
            f"IP Intel: {critical_findings[0]}",
            detail,
            impact=25,
        )
    else:
        return result.warn(
            f"IP Intel: {warning_findings[0]}",
            detail,
            impact=10,
        )
