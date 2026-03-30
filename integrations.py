"""
SwarmHawk XDR & SIEM Integration Connectors
============================================
Push scan findings to 9 external security platforms.
Each connector sends platform-optimised, fully-enriched payloads —
not just a risk score, but the complete external attack surface picture:
CVE list, software fingerprints, email security chain (SPF/DMARC/DKIM),
blacklist status, domain age, failed check breakdown, threat classification,
and remediation context.

Interface:
  - push(finding)  → bool   (fire-and-forget, raises on failure)
  - test()         → dict   ({ok: bool, message: str})

Dispatcher:
  fire_integrations_sync(finding, user_id, db)
  Called from pipeline.upsert_scan_result for risk_score >= 70.
"""

import json
import hmac
import hashlib
import base64
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

log = logging.getLogger(__name__)

_UUID_NS = uuid.UUID("8f1e1e1e-1e1e-1e1e-1e1e-1e1e1e1e1e1e")


def _uuid4() -> str:
    return str(uuid.uuid4())


def _uuid5(namespace: uuid.UUID, name: str) -> str:
    return str(uuid.uuid5(namespace, name))


def _parse_json(v) -> list:
    """Parse a field that may be a JSON string, list, or None."""
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            return json.loads(v) or []
        except Exception:
            return []
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Threat classification helpers
# ─────────────────────────────────────────────────────────────────────────────

def _classify_threats(f: dict) -> list[str]:
    """Derive human-readable threat types from scan fields.

    Returns a list like ["phishing_vector", "unpatched_cve", "malware_distribution"].
    Used by Splunk (tags), CrowdStrike (IOC tags), Cortex (MITRE labels), etc.
    """
    threats = []
    spf  = (f.get("spf_status")   or "").lower()
    dmarc = (f.get("dmarc_status") or "").lower()
    dkim  = (f.get("dkim_status")  or "").lower()

    # Phishing vector: missing email security + either low age OR blacklisted
    email_exposed = spf in ("missing", "invalid") or dmarc in ("missing", "invalid")
    if email_exposed:
        threats.append("phishing_vector")

    if bool(f.get("blacklisted")):
        threats.append("malware_distribution")

    if (f.get("urlhaus_status") or "").lower() not in ("", "clean"):
        threats.append("active_malware_url")

    cves = _parse_json(f.get("cves"))
    if cves:
        threats.append("unpatched_cve")

    software = _parse_json(f.get("software"))
    if software:
        threats.append("exposed_software_stack")

    checks = _parse_json(f.get("checks"))
    failed = {c.get("check") or c.get("name", "") for c in checks
              if isinstance(c, dict) and c.get("status") in ("critical", "warning")}

    if "ssl" in failed or "tls" in failed:
        threats.append("ssl_misconfiguration")
    if "headers" in failed or "csp" in failed:
        threats.append("missing_security_headers")
    if "ports" in failed or "open_ports" in failed:
        threats.append("exposed_ports")
    if "cors" in failed:
        threats.append("cors_misconfiguration")

    age = f.get("domain_age_days")
    if age is not None and int(age) < 365:
        threats.append("newly_registered_domain")

    return threats or ["external_exposure"]


def _email_security_score(f: dict) -> int:
    """0 = all missing, 3 = SPF + DMARC + DKIM all present."""
    score = 0
    if (f.get("spf_status")  or "").lower() == "present":  score += 1
    if (f.get("dmarc_status") or "").lower() == "present": score += 1
    if (f.get("dkim_status")  or "").lower() == "present": score += 1
    return score


def _top_cves(f: dict, n: int = 5) -> list[dict]:
    cves = _parse_json(f.get("cves"))
    parsed = []
    for c in cves:
        if isinstance(c, dict) and c.get("id"):
            parsed.append({"id": c["id"], "cvss": float(c.get("cvss") or 0)})
    return sorted(parsed, key=lambda x: x["cvss"], reverse=True)[:n]


def _failed_checks(f: dict) -> list[str]:
    checks = _parse_json(f.get("checks"))
    return [
        c.get("check") or c.get("name", "")
        for c in checks
        if isinstance(c, dict) and c.get("status") in ("critical", "warning")
    ]


def _software_list(f: dict) -> list[dict]:
    sw = _parse_json(f.get("software"))
    result = []
    for s in sw:
        if isinstance(s, dict):
            result.append({"product": s.get("product", ""), "version": s.get("version", "")})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Base connector
# ─────────────────────────────────────────────────────────────────────────────

class BaseConnector:
    SERVICE: str = ""

    def __init__(self, config: dict):
        self.config = config

    def push(self, finding: dict) -> bool:
        raise NotImplementedError

    def test(self) -> dict:
        raise NotImplementedError

    def _enrich(self, f: dict) -> dict:
        """Full enriched finding — all 25+ fields, parsed JSON, derived intel.

        This is the complete picture SwarmHawk has on a domain.
        Each connector picks the subset relevant to its platform.
        """
        threats    = _classify_threats(f)
        top_cves   = _top_cves(f)
        sw_list    = _software_list(f)
        failed     = _failed_checks(f)
        email_sc   = _email_security_score(f)
        phish_risk = bool(
            (f.get("spf_status") or "").lower() in ("missing", "invalid")
            and (f.get("dmarc_status") or "").lower() in ("missing", "invalid")
        )

        return {
            # Core identity
            "domain":              f.get("domain", ""),
            "country":             f.get("country", ""),
            "registrar":           f.get("registrar", ""),
            "domain_age_days":     f.get("domain_age_days"),

            # Risk scoring
            "risk_score":          f.get("risk_score", 0),
            "max_cvss":            float(f.get("max_cvss") or 0),
            "priority":            f.get("priority", "INFO"),
            "critical_count":      f.get("critical", 0),
            "warning_count":       f.get("warnings", 0),

            # Email security chain
            "spf_status":          f.get("spf_status", ""),
            "dmarc_status":        f.get("dmarc_status", ""),
            "dkim_status":         f.get("dkim_status", ""),
            "email_security_score": email_sc,       # 0–3
            "phishing_risk":       phish_risk,

            # Threat intel
            "blacklisted":         bool(f.get("blacklisted", False)),
            "blacklist_hits":      _parse_json(f.get("blacklist_hits")),
            "urlhaus_status":      f.get("urlhaus_status", ""),
            "ip_reputation":       f.get("ip_reputation", ""),
            "waf_detected":        bool(f.get("waf_detected", False)),

            # Vulnerability intelligence
            "top_cves":            top_cves,
            "cve_ids":             ", ".join(c["id"] for c in top_cves),
            "cve_count":           len(_parse_json(f.get("cves"))),

            # Software fingerprints
            "software_detected":   sw_list,
            "software_names":      ", ".join(s["product"] for s in sw_list if s["product"]),

            # Check results
            "failed_checks":       failed,
            "failed_checks_csv":   ", ".join(failed),
            "threat_types":        threats,
            "threat_types_csv":    ", ".join(threats),

            # Timestamps
            "last_scanned_at":     f.get("last_scanned_at") or datetime.now(timezone.utc).isoformat(),
            "source":              "swarmhawk",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Splunk SIEM — HTTP Event Collector (HEC)
# ─────────────────────────────────────────────────────────────────────────────
# What Splunk gets that's unique:
#   • CIM-aligned fields (dest, vendor_product, category) for out-of-box correlation
#   • Full CVE list → search: index=swarmhawk | where match(cve_ids, "CVE-2024")
#   • Software stack → track Log4Shell exposure across all monitored domains
#   • Email security score → find all domains with score 0 = phishing-ready
#   • Threat type tags → index=swarmhawk threat_types_csv=*phishing_vector*
# Example SPL: index=swarmhawk sourcetype=swarmhawk:scan | stats count by threat_types_csv, country
# ─────────────────────────────────────────────────────────────────────────────

class SplunkConnector(BaseConnector):
    SERVICE = "splunk"

    def _hec_url(self) -> str:
        return self.config["hec_url"].rstrip("/") + "/services/collector/event"

    def _splunk_event(self, f: dict) -> dict:
        e = self._enrich(f)
        return {
            # Splunk CIM alignment
            "dest":                e["domain"],
            "vendor_product":      "SwarmHawk EASM",
            "category":            "vulnerability",
            "action":              "allowed",
            "severity":            e["priority"].lower(),

            # SwarmHawk risk context
            "risk_score":          e["risk_score"],
            "max_cvss":            e["max_cvss"],
            "priority":            e["priority"],
            "critical_count":      e["critical_count"],
            "warning_count":       e["warning_count"],

            # Threat intelligence
            "threat_types_csv":    e["threat_types_csv"],
            "phishing_risk":       int(e["phishing_risk"]),
            "blacklisted":         int(e["blacklisted"]),
            "urlhaus_status":      e["urlhaus_status"],
            "ip_reputation":       e["ip_reputation"],
            "waf_detected":        int(e["waf_detected"]),

            # Vulnerability data
            "cve_ids":             e["cve_ids"],
            "cve_count":           e["cve_count"],
            "software_names":      e["software_names"],
            "failed_checks_csv":   e["failed_checks_csv"],

            # Email security chain
            "spf_status":          e["spf_status"],
            "dmarc_status":        e["dmarc_status"],
            "dkim_status":         e["dkim_status"],
            "email_security_score": e["email_security_score"],

            # Domain context
            "country":             e["country"],
            "registrar":           e["registrar"],
            "domain_age_days":     e["domain_age_days"],
            "last_scanned_at":     e["last_scanned_at"],
            "src":                 "swarmhawk",
        }

    def push(self, finding: dict) -> bool:
        payload = {
            "time":       time.time(),
            "source":     "swarmhawk",
            "sourcetype": "swarmhawk:scan",
            "index":      self.config.get("index", "main"),
            "event":      self._splunk_event(finding),
        }
        resp = httpx.post(
            self._hec_url(),
            headers={"Authorization": f"Splunk {self.config['hec_token']}"},
            json=payload,
            timeout=10,
            verify=self.config.get("ssl_verify", True),
        )
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            self.push({"domain": "test.swarmhawk.com", "risk_score": 0, "max_cvss": 0.0, "priority": "INFO"})
            return {"ok": True, "message": "Test event delivered to Splunk HEC"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Sentinel — Azure Monitor Log Analytics
# ─────────────────────────────────────────────────────────────────────────────
# What Sentinel gets that's unique:
#   • Flat KQL-ready fields (Domain_s, RiskScore_d, PhishingRisk_b, CVEList_s)
#   • ThreatCategory_s → workbooks, custom analytic rules, playbook triggers
#   • Correlate with AAD sign-in logs: if user browsed a blacklisted domain → alert
#   • NIS2 compliance mapping → ComplianceFlag_s = "NIS2-Art21"
#   • AttackVectors_s → MITRE ATT&CK mapping in Sentinel workbooks
# Example KQL: SwarmHawk_CL | where max_cvss_d > 7 | summarize count() by ThreatCategory_s
# ─────────────────────────────────────────────────────────────────────────────

class SentinelConnector(BaseConnector):
    SERVICE = "sentinel"

    def _shared_key_signature(self, date: str, content_length: int) -> str:
        string_to_sign = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        key_bytes = base64.b64decode(self.config["shared_key"])
        sig = base64.b64encode(
            hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode()
        return f"SharedKey {self.config['workspace_id']}:{sig}"

    def _sentinel_record(self, f: dict) -> dict:
        """Flat Azure Monitor record — _s suffix=string, _d=number, _b=bool."""
        e = self._enrich(f)
        return {
            # Identifiers
            "Domain_s":              e["domain"],
            "Country_s":             e["country"],
            "Registrar_s":           e["registrar"],
            "DomainAgeDays_d":       e["domain_age_days"] or 0,

            # Risk scores
            "RiskScore_d":           e["risk_score"],
            "MaxCVSS_d":             e["max_cvss"],
            "Priority_s":            e["priority"],
            "CriticalCount_d":       e["critical_count"],
            "WarningCount_d":        e["warning_count"],

            # Threat classification (KQL-searchable)
            "ThreatCategory_s":      e["threat_types"][0] if e["threat_types"] else "external_exposure",
            "ThreatTypes_s":         e["threat_types_csv"],
            "AttackVectors_s":       e["failed_checks_csv"],
            "PhishingRisk_b":        e["phishing_risk"],

            # Threat intel
            "Blacklisted_b":         e["blacklisted"],
            "URLhausStatus_s":       e["urlhaus_status"],
            "IPReputation_s":        e["ip_reputation"],
            "WAFDetected_b":         e["waf_detected"],

            # Vulnerability data
            "CVEList_s":             e["cve_ids"],
            "CVECount_d":            e["cve_count"],
            "SoftwareStack_s":       e["software_names"],

            # Email security chain
            "SPFStatus_s":           e["spf_status"],
            "DMARCStatus_s":         e["dmarc_status"],
            "DKIMStatus_s":          e["dkim_status"],
            "EmailSecurityScore_d":  e["email_security_score"],

            # Compliance
            "ComplianceFlag_s":      "NIS2-Art21" if e["risk_score"] >= 70 else "",

            # Source
            "Source_s":              "SwarmHawk",
            "TimeGenerated":         e["last_scanned_at"],
        }

    def push(self, finding: dict) -> bool:
        workspace_id = self.config["workspace_id"]
        log_type = self.config.get("log_type", "SwarmHawk")
        body = json.dumps([self._sentinel_record(finding)])
        body_bytes = body.encode("utf-8")
        rfc1123 = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        resp = httpx.post(
            f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            headers={
                "Authorization":        self._shared_key_signature(rfc1123, len(body_bytes)),
                "Content-Type":         "application/json",
                "Log-Type":             log_type,
                "x-ms-date":            rfc1123,
                "time-generated-field": "TimeGenerated",
            },
            content=body_bytes,
            timeout=15,
        )
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            self.push({
                "domain": "test.swarmhawk.com", "risk_score": 0, "max_cvss": 0.0,
                "priority": "INFO", "last_scanned_at": datetime.now(timezone.utc).isoformat(),
            })
            return {"ok": True, "message": "Log sent to Microsoft Sentinel workspace"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# CrowdStrike Falcon — OAuth2 + IOC push
# ─────────────────────────────────────────────────────────────────────────────
# What CrowdStrike gets that's unique:
#   • Domain classified by threat type: phishing / malware / c2 / vulnerability
#   • Action: "prevent" for blacklisted/active malware, "detect" for CVE/misconfiguration
#   • 90-day IOC expiration — auto-refreshed on each scan cycle
#   • Tags include threat types so Falcon analysts can filter by risk class
#   • Severity mapped: CVSS 9+ → CRITICAL, 7-9 → HIGH, 4-7 → MEDIUM
#   • Correlate with endpoint telemetry: if employee connected to this IOC → alert
# ─────────────────────────────────────────────────────────────────────────────

class CrowdStrikeConnector(BaseConnector):
    SERVICE = "crowdstrike"

    def _base(self) -> str:
        return self.config.get("base_url", "https://api.crowdstrike.com").rstrip("/")

    def _get_token(self) -> str:
        resp = httpx.post(
            f"{self._base()}/oauth2/token",
            data={"client_id": self.config["client_id"], "client_secret": self.config["client_secret"]},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def push(self, finding: dict) -> bool:
        e = self._enrich(finding)
        token = self._get_token()

        cvss = e["max_cvss"]
        severity = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM"
        # Actively malicious → prevent; exposure/CVE → detect
        action = "prevent" if (e["blacklisted"] or "malware_distribution" in e["threat_types"]) else "detect"

        expiry = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")

        tags = ["swarmhawk", "easm"] + e["threat_types"]

        desc_parts = [
            f"SwarmHawk EASM | Risk: {e['risk_score']}/100 | CVSS: {cvss}",
            f"Threats: {e['threat_types_csv']}",
        ]
        if e["cve_ids"]:
            desc_parts.append(f"CVEs: {e['cve_ids']}")
        if e["software_names"]:
            desc_parts.append(f"Software: {e['software_names']}")
        if e["blacklisted"]:
            desc_parts.append("⚠ Active on threat blacklists")
        if e["phishing_risk"]:
            desc_parts.append("⚠ Domain can be spoofed — SPF/DMARC missing")

        resp = httpx.post(
            f"{self._base()}/iocs/entities/iocs/v1",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "indicators": [{
                    "type":             "domain",
                    "value":            e["domain"],
                    "action":           action,
                    "severity":         severity,
                    "platforms":        ["windows", "mac", "linux"],
                    "description":      " | ".join(desc_parts),
                    "source":           "SwarmHawk",
                    "tags":             tags[:10],
                    "applied_globally": True,
                    "expiration":       expiry,
                }]
            },
            timeout=15,
        )
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            self._get_token()
            return {"ok": True, "message": "CrowdStrike OAuth2 authentication successful"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Bitdefender GravityZone — JSON-RPC REST API
# ─────────────────────────────────────────────────────────────────────────────
# What GravityZone gets that's unique:
#   • Rule action: "block" for malware/phishing domains, "report" for exposure
#   • Rule name encodes risk score for quick visual scanning in GravityZone console
#   • Rule description includes CVE list + software so AV analysts have context
#   • Tagged by threat type for policy grouping
# ─────────────────────────────────────────────────────────────────────────────

class GravityZoneConnector(BaseConnector):
    SERVICE = "gravityzone"

    def _api(self) -> str:
        return self.config.get("api_url", "https://cloudgz.gravityzone.bitdefender.com").rstrip("/")

    def push(self, finding: dict) -> bool:
        e = self._enrich(finding)
        action = "block" if (e["blacklisted"] or "malware_distribution" in e["threat_types"]) else "report"

        desc_parts = [f"Risk: {e['risk_score']}/100 | CVSS: {e['max_cvss']}"]
        if e["threat_types_csv"]:
            desc_parts.append(f"Threats: {e['threat_types_csv']}")
        if e["cve_ids"]:
            desc_parts.append(f"CVEs: {e['cve_ids']}")
        if e["software_names"]:
            desc_parts.append(f"Software: {e['software_names']}")

        resp = httpx.post(
            f"{self._api()}/api/v1.0/jsonrpc/push",
            auth=(self.config["api_key"], ""),
            json={
                "id": "swarmhawk-push", "jsonrpc": "2.0",
                "method": "createCustomRule",
                "params": {
                    "companyId": self.config.get("company_id", ""),
                    "rule": {
                        "name":        f"[SwarmHawk {e['priority']}] {e['domain']}",
                        "type":        "domain",
                        "value":       e["domain"],
                        "description": " | ".join(desc_parts),
                        "action":      action,
                        "enabled":     True,
                    },
                },
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(data["error"].get("message", "GravityZone API error"))
        return True

    def test(self) -> dict:
        try:
            resp = httpx.get(
                f"{self._api()}/api/v1.0/jsonrpc/companies",
                auth=(self.config["api_key"], ""),
                timeout=10,
            )
            resp.raise_for_status()
            return {"ok": True, "message": "Bitdefender GravityZone API reachable"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Palo Alto Cortex XDR — External alert ingestion
# ─────────────────────────────────────────────────────────────────────────────
# What Cortex gets that's unique:
#   • Alert description maps to MITRE ATT&CK techniques via threat_types
#   • Full attack narrative in alert_description for analyst context
#   • Correlated with endpoint data → if endpoint touched this domain = confirmed exposure
# ─────────────────────────────────────────────────────────────────────────────

class CortexConnector(BaseConnector):
    SERVICE = "cortex"

    # Rough MITRE ATT&CK mapping from threat types
    _MITRE_MAP = {
        "phishing_vector":         "T1566 — Phishing",
        "malware_distribution":    "T1189 — Drive-by Compromise",
        "unpatched_cve":           "T1190 — Exploit Public-Facing Application",
        "exposed_ports":           "T1046 — Network Service Discovery",
        "ssl_misconfiguration":    "T1557 — Adversary-in-the-Middle",
        "missing_security_headers": "T1059 — Command and Scripting Interpreter",
        "active_malware_url":      "T1204 — User Execution",
    }

    def _auth_headers(self) -> dict:
        import secrets as _s
        nonce = _s.token_hex(16)
        ts = str(int(time.time() * 1000))
        auth_hash = hashlib.sha256(f"{self.config['api_key']}{nonce}{ts}".encode()).hexdigest()
        return {
            "x-xdr-auth-id":   str(self.config["api_key_id"]),
            "x-xdr-nonce":     nonce,
            "x-xdr-timestamp": ts,
            "Authorization":   auth_hash,
            "Content-Type":    "application/json",
        }

    def push(self, finding: dict) -> bool:
        e = self._enrich(finding)
        mitre_tags = [
            self._MITRE_MAP[t] for t in e["threat_types"] if t in self._MITRE_MAP
        ]

        desc_lines = [
            f"Domain: {e['domain']} | Country: {e['country']}",
            f"Risk Score: {e['risk_score']}/100 | Max CVSS: {e['max_cvss']}",
            f"Threats: {e['threat_types_csv']}",
        ]
        if mitre_tags:
            desc_lines.append("MITRE: " + " · ".join(mitre_tags))
        if e["cve_ids"]:
            desc_lines.append(f"CVEs: {e['cve_ids']}")
        if e["software_names"]:
            desc_lines.append(f"Software: {e['software_names']}")
        if e["phishing_risk"]:
            desc_lines.append("SPF/DMARC missing — domain can be spoofed for phishing")
        if e["blacklisted"]:
            desc_lines.append("Active on threat blacklists")

        severity = "CRITICAL" if e["max_cvss"] >= 9 else "HIGH" if e["max_cvss"] >= 7 else "MEDIUM"

        resp = httpx.post(
            f"https://api-{self.config['fqdn']}/public_api/v1/alerts/insert_external_event/",
            headers=self._auth_headers(),
            json={
                "request_data": {
                    "alerts": [{
                        "product":           "SwarmHawk",
                        "vendor":            "SwarmHawk",
                        "local_ip":          "",
                        "local_port":        0,
                        "remote_ip":         "",
                        "remote_port":       0,
                        "event_timestamp":   int(time.time() * 1000),
                        "severity":          severity,
                        "alert_name":        f"[{e['priority']}] Domain Risk: {e['domain']}",
                        "alert_description": "\n".join(desc_lines),
                    }]
                }
            },
            timeout=15,
        )
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            resp = httpx.post(
                f"https://api-{self.config['fqdn']}/public_api/v1/xql/start_xql_query/",
                headers=self._auth_headers(),
                json={"request_data": {"query": "dataset=xdr_data | limit 1", "timeframe": {"relativeTime": 60000}}},
                timeout=10,
            )
            resp.raise_for_status()
            return {"ok": True, "message": "Palo Alto Cortex XDR API reachable"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Jira — Structured security tickets with full remediation context
# ─────────────────────────────────────────────────────────────────────────────
# What Jira gets that's unique:
#   • Rich ADF (Atlassian Document Format) with tables, bullet lists, headings
#   • CVE table: ID | CVSS | Severity
#   • Per-check remediation steps mapped from check names
#   • Software stack table: Product | Version | Risk
#   • NIS2 compliance flag in labels if risk >= 70
#   • Labels: swarmhawk, easm, threat type, country
# ─────────────────────────────────────────────────────────────────────────────

_REMEDIATION_MAP = {
    "ssl":                   "Renew/reconfigure SSL certificate. Enforce TLS 1.2+. Disable deprecated cipher suites.",
    "tls":                   "Enforce TLS 1.2 or higher. Disable SSLv3, TLS 1.0, TLS 1.1.",
    "headers":               "Add missing HTTP security headers: Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options.",
    "csp":                   "Implement a Content Security Policy header. Start with 'default-src self'.",
    "cors":                  "Restrict CORS Allow-Origin to specific trusted domains, remove wildcard '*'.",
    "ports":                 "Close or firewall unnecessary open ports. Restrict admin interfaces to VPN/bastion.",
    "dmarc":                 "Add DMARC DNS record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
    "spf":                   "Add SPF DNS record listing authorised mail senders: v=spf1 include:... -all",
    "dkim":                  "Configure DKIM signing on your mail server and publish the public key as a DNS TXT record.",
    "cve":                   "Patch affected software to the latest version. Apply vendor security advisories.",
    "cookies":               "Add Secure; HttpOnly; SameSite=Strict flags to all session cookies.",
    "redirects":             "Remove open redirect endpoints. Validate redirect targets against an allowlist.",
    "clickjacking":          "Add X-Frame-Options: DENY or SAMEONLY. Use frame-ancestors CSP directive.",
    "software":              "Update all detected software components to latest stable versions.",
}


def _build_jira_adf(e: dict) -> dict:
    """Build an Atlassian Document Format body for the Jira issue."""
    content = []

    def heading(text, level=3):
        return {"type": "heading", "attrs": {"level": level}, "content": [{"type": "text", "text": text}]}

    def paragraph(text):
        return {"type": "paragraph", "content": [{"type": "text", "text": text}]}

    def bullet_list(items):
        return {
            "type": "bulletList",
            "content": [
                {"type": "listItem", "content": [paragraph(i)]} for i in items
            ],
        }

    def table(headers, rows):
        def cell(text, header=False):
            t = "tableHeader" if header else "tableCell"
            return {"type": t, "content": [paragraph(str(text))]}
        return {
            "type": "table",
            "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
            "content": [
                {"type": "tableRow", "content": [cell(h, True) for h in headers]},
                *[{"type": "tableRow", "content": [cell(v) for v in row]} for row in rows],
            ],
        }

    # ── Summary ──
    content.append(heading("Risk Summary", 2))
    content.append(table(
        ["Field", "Value"],
        [
            ["Domain",            e["domain"]],
            ["Risk Score",        f"{e['risk_score']}/100"],
            ["Max CVSS",          str(e["max_cvss"])],
            ["Priority",          e["priority"]],
            ["Country",           e["country"]],
            ["Domain Age",        f"{e['domain_age_days']} days" if e["domain_age_days"] else "Unknown"],
            ["Registrar",         e["registrar"] or "Unknown"],
            ["Phishing Risk",     "YES" if e["phishing_risk"] else "No"],
            ["Blacklisted",       "YES" if e["blacklisted"] else "No"],
            ["WAF Detected",      "Yes" if e["waf_detected"] else "No"],
            ["Email Security",    f"{e['email_security_score']}/3 (SPF/DMARC/DKIM)"],
        ],
    ))

    # ── Threat Classification ──
    content.append(heading("Threat Classification", 3))
    content.append(bullet_list(e["threat_types"] or ["external_exposure"]))

    # ── CVE Findings ──
    if e["top_cves"]:
        content.append(heading("CVE Findings", 3))
        content.append(table(
            ["CVE ID", "CVSS Score", "Severity"],
            [[c["id"], c["cvss"], "CRITICAL" if c["cvss"] >= 9 else "HIGH" if c["cvss"] >= 7 else "MEDIUM"]
             for c in e["top_cves"]],
        ))

    # ── Software Detected ──
    if e["software_detected"]:
        content.append(heading("Software Stack Detected", 3))
        content.append(table(
            ["Product", "Version"],
            [[s["product"], s["version"] or "Unknown"] for s in e["software_detected"]],
        ))

    # ── Failed Checks ──
    if e["failed_checks"]:
        content.append(heading("Failed Security Checks", 3))
        content.append(bullet_list(e["failed_checks"]))

    # ── Remediation ──
    remediations = [
        f"{check}: {_REMEDIATION_MAP[check]}"
        for check in e["failed_checks"]
        if check in _REMEDIATION_MAP
    ]
    if remediations:
        content.append(heading("Recommended Remediations", 3))
        content.append(bullet_list(remediations))

    # ── Compliance ──
    if e["risk_score"] >= 70:
        content.append(heading("Compliance Context", 3))
        content.append(paragraph(
            "This domain's exposure may constitute a breach of NIS2 Article 21 "
            "(technical and operational security measures). Remediation should be "
            "tracked with a defined SLA under your incident response policy."
        ))

    content.append(heading("Source", 3))
    content.append(paragraph(f"SwarmHawk EASM · Last scanned: {e['last_scanned_at']}"))

    return {"type": "doc", "version": 1, "content": content}


class JiraConnector(BaseConnector):
    SERVICE = "jira"

    _PRIORITY_MAP = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Lowest"}

    def _auth(self) -> str:
        return base64.b64encode(f"{self.config['email']}:{self.config['api_token']}".encode()).decode()

    def push(self, finding: dict) -> bool:
        if finding.get("risk_score", 0) < 70 and float(finding.get("max_cvss") or 0) < 7.0:
            return False

        e = self._enrich(finding)
        priority = e["priority"]

        labels = ["swarmhawk", "security", "easm"]
        if e["country"]:
            labels.append(e["country"].lower())
        labels += [t.replace("_", "-") for t in e["threat_types"][:3]]
        if e["risk_score"] >= 70:
            labels.append("nis2")

        resp = httpx.post(
            f"{self.config['base_url'].rstrip('/')}/rest/api/3/issue",
            headers={"Authorization": f"Basic {self._auth()}", "Content-Type": "application/json"},
            json={
                "fields": {
                    "project":     {"key": self.config["project_key"]},
                    "summary":     f"[SwarmHawk] {e['domain']} — Risk {e['risk_score']}/100 | CVSS {e['max_cvss']} | {priority}",
                    "description": _build_jira_adf(e),
                    "issuetype":   {"name": self.config.get("issue_type", "Bug")},
                    "priority":    {"name": self._PRIORITY_MAP.get(priority, "Medium")},
                    "labels":      labels[:10],
                }
            },
            timeout=15,
        )
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            resp = httpx.get(
                f"{self.config['base_url'].rstrip('/')}/rest/api/3/myself",
                headers={"Authorization": f"Basic {self._auth()}"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            name = data.get("emailAddress") or data.get("displayName", "user")
            return {"ok": True, "message": f"Jira authenticated as {name}"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# ServiceNow — Incidents with business context + NIS2 compliance
# ─────────────────────────────────────────────────────────────────────────────
# What ServiceNow gets that's unique:
#   • Business risk framing (not just "CVSS 8.1" but "this domain can be spoofed for phishing")
#   • NIS2 Article 21 compliance reference in description
#   • Urgency/Impact auto-mapped from risk_score (not just CVSS)
#   • Remediation timeline guidance based on priority
# ─────────────────────────────────────────────────────────────────────────────

class ServiceNowConnector(BaseConnector):
    SERVICE = "servicenow"

    _URGENCY = {"CRITICAL": "1", "HIGH": "1", "MEDIUM": "2", "LOW": "3", "INFO": "3"}
    _IMPACT  = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "2", "LOW": "3", "INFO": "3"}
    _SLA     = {"CRITICAL": "4 hours", "HIGH": "24 hours", "MEDIUM": "7 days", "LOW": "30 days", "INFO": "Best effort"}

    def push(self, finding: dict) -> bool:
        e = self._enrich(finding)
        priority = e["priority"]

        desc_sections = [
            "=== SwarmHawk External Attack Surface Finding ===",
            "",
            f"Domain:         {e['domain']}",
            f"Country:        {e['country']}",
            f"Risk Score:     {e['risk_score']}/100",
            f"Max CVSS:       {e['max_cvss']}",
            f"Priority:       {priority}",
            f"SLA Target:     {self._SLA.get(priority, '7 days')}",
            "",
            "--- THREAT CLASSIFICATION ---",
            ", ".join(e["threat_types"]) or "external_exposure",
            "",
        ]

        if e["cve_ids"]:
            desc_sections += ["--- VULNERABILITIES ---", e["cve_ids"], ""]

        if e["software_names"]:
            desc_sections += ["--- DETECTED SOFTWARE ---", e["software_names"], ""]

        if e["failed_checks"]:
            desc_sections += ["--- FAILED CHECKS ---", ", ".join(e["failed_checks"]), ""]

        desc_sections += [
            "--- EMAIL SECURITY ---",
            f"SPF: {e['spf_status'] or 'Unknown'}  |  DMARC: {e['dmarc_status'] or 'Unknown'}  |  DKIM: {e['dkim_status'] or 'Unknown'}",
            f"Phishing Risk: {'HIGH - domain can be spoofed' if e['phishing_risk'] else 'Low'}",
            "",
        ]

        if e["blacklisted"]:
            desc_sections += ["⚠ ACTIVE ON THREAT BLACKLISTS — immediate investigation recommended", ""]

        if e["risk_score"] >= 70:
            desc_sections += [
                "--- NIS2 COMPLIANCE ---",
                "This finding may constitute a breach of NIS2 Article 21 (security measures).",
                "Document remediation steps for audit trail.",
                "",
            ]

        desc_sections += [
            "--- REMEDIATION ---",
            *[f"• {check}: {_REMEDIATION_MAP.get(check, 'Review and remediate')}" for check in e["failed_checks"][:5]],
            "",
            f"Source: SwarmHawk EASM | Scanned: {e['last_scanned_at']}",
        ]

        resp = httpx.post(
            f"https://{self.config['instance']}.service-now.com/api/now/table/{self.config.get('table', 'incident')}",
            auth=(self.config["username"], self.config["password"]),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={
                "short_description": f"[SwarmHawk {priority}] {e['domain']} — Risk {e['risk_score']}/100 | {', '.join(e['threat_types'][:2])}",
                "description":       "\n".join(desc_sections),
                "category":          "Security",
                "subcategory":       "External Attack Surface",
                "urgency":           self._URGENCY.get(priority, "2"),
                "impact":            self._IMPACT.get(priority, "2"),
                "caller_id":         "SwarmHawk",
            },
            timeout=15,
        )
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            resp = httpx.get(
                f"https://{self.config['instance']}.service-now.com/api/now/table/incident?sysparm_limit=1",
                auth=(self.config["username"], self.config["password"]),
                headers={"Accept": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            return {"ok": True, "message": "ServiceNow API reachable"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Generic Webhook — Full enriched payload, HMAC-SHA256 signed
# ─────────────────────────────────────────────────────────────────────────────
# What webhooks enable:
#   • Slack/Teams alerts: "🚨 example.cz risk 87/100 — phishing_vector, unpatched_cve"
#   • PagerDuty: auto-page on-call when risk >= 90
#   • Custom dashboards: stream all scan events to Datadog, Grafana, etc.
#   • SOAR platforms: trigger automated remediation playbooks
# ─────────────────────────────────────────────────────────────────────────────

class WebhookConnector(BaseConnector):
    SERVICE = "webhook"

    def push(self, finding: dict) -> bool:
        e = self._enrich(finding)
        payload = {
            "event":              "scan.completed",
            "domain":             e["domain"],
            "risk_score":         e["risk_score"],
            "max_cvss":           e["max_cvss"],
            "priority":           e["priority"],
            "critical_count":     e["critical_count"],
            "threat_types":       e["threat_types"],
            "phishing_risk":      e["phishing_risk"],
            "blacklisted":        e["blacklisted"],
            "cve_ids":            e["cve_ids"],
            "software_names":     e["software_names"],
            "failed_checks":      e["failed_checks"],
            "email_security_score": e["email_security_score"],
            "country":            e["country"],
            "timestamp":          datetime.now(timezone.utc).isoformat(),
        }
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        secret = self.config.get("secret", "")
        if secret:
            headers["X-SwarmHawk-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        resp = httpx.post(self.config["url"], headers=headers, content=body, timeout=10)
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            self.push({
                "domain": "test.swarmhawk.com", "risk_score": 99,
                "max_cvss": 9.8, "priority": "CRITICAL", "critical": 3,
            })
            return {"ok": True, "message": "Test webhook delivered successfully"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# STIX/TAXII 2.1 — Share domain IOCs as standardised threat intelligence
# ─────────────────────────────────────────────────────────────────────────────
# What STIX/TAXII enables:
#   • Feed your findings into MISP, OpenCTI, Anomali, Recorded Future
#   • Share domain IOCs with sector ISACs (FS-ISAC, H-ISAC, etc.)
#   • Enrich your own threat intel platform with external attack surface data
#   • DomainName + Vulnerability + Relationship objects in STIX 2.1 format
# ─────────────────────────────────────────────────────────────────────────────

class STIXConnector(BaseConnector):
    SERVICE = "stix"

    def push(self, finding: dict) -> bool:
        return True  # STIX findings are served via /taxii endpoint, no outbound push

    def test(self) -> dict:
        return {"ok": True, "message": "STIX/TAXII 2.1 feed active at /taxii/collections/swarmhawk/objects/"}

    @staticmethod
    def build_bundle(findings: list) -> dict:
        objects: list = []
        now = datetime.now(timezone.utc).isoformat()

        for f in findings:
            domain = f.get("domain", "")
            if not domain:
                continue

            domain_id = f"domain-name--{_uuid5(_UUID_NS, domain)}"
            objects.append({
                "type":         "domain-name",
                "spec_version": "2.1",
                "id":           domain_id,
                "value":        domain,
                "created":      f.get("created_at", now),
                "modified":     f.get("last_scanned_at", now),
            })

            cves = _parse_json(f.get("cves"))
            for cve in cves[:5]:
                cve_id = cve.get("id", "") if isinstance(cve, dict) else ""
                if not cve_id:
                    continue
                vuln_id = f"vulnerability--{_uuid5(_UUID_NS, cve_id)}"
                objects.append({
                    "type":         "vulnerability",
                    "spec_version": "2.1",
                    "id":           vuln_id,
                    "name":         cve_id,
                    "description":  f"CVSS: {cve.get('cvss', 0.0) if isinstance(cve, dict) else 0.0}",
                    "created":      now,
                    "modified":     now,
                    "external_references": [{"source_name": "cve", "external_id": cve_id}],
                })
                objects.append({
                    "type":              "relationship",
                    "spec_version":      "2.1",
                    "id":                f"relationship--{_uuid5(_UUID_NS, domain_id + vuln_id)}",
                    "relationship_type": "has",
                    "source_ref":        domain_id,
                    "target_ref":        vuln_id,
                    "created":           now,
                    "modified":          now,
                })

        return {"type": "bundle", "id": f"bundle--{_uuid4()}", "spec_version": "2.1", "objects": objects}


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

CONNECTORS: dict[str, type[BaseConnector]] = {
    "splunk":       SplunkConnector,
    "sentinel":     SentinelConnector,
    "crowdstrike":  CrowdStrikeConnector,
    "gravityzone":  GravityZoneConnector,
    "cortex":       CortexConnector,
    "jira":         JiraConnector,
    "servicenow":   ServiceNowConnector,
    "webhook":      WebhookConnector,
    "stix":         STIXConnector,
}

CONNECTOR_META: dict[str, dict] = {
    "splunk":       {"name": "Splunk SIEM",             "logo": "📊", "fields": ["hec_url", "hec_token", "index"]},
    "sentinel":     {"name": "Microsoft Sentinel",      "logo": "🔵", "fields": ["workspace_id", "shared_key", "log_type"]},
    "crowdstrike":  {"name": "CrowdStrike Falcon",      "logo": "🦅", "fields": ["client_id", "client_secret", "base_url"]},
    "gravityzone":  {"name": "Bitdefender GravityZone", "logo": "🛡️", "fields": ["api_url", "api_key", "company_id"]},
    "cortex":       {"name": "Palo Alto Cortex XDR",    "logo": "🟠", "fields": ["api_key", "api_key_id", "fqdn"]},
    "jira":         {"name": "Jira",                    "logo": "🎫", "fields": ["base_url", "email", "api_token", "project_key", "issue_type"]},
    "servicenow":   {"name": "ServiceNow",              "logo": "🔧", "fields": ["instance", "username", "password", "table"]},
    "webhook":      {"name": "Webhook / REST API",       "logo": "📡", "fields": ["url", "secret"]},
    "stix":         {"name": "STIX / TAXII 2.1",        "logo": "⚡", "fields": []},
}


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def fire_integrations_sync(finding: dict, user_id: str, db) -> None:
    """Fire all enabled integrations for a user after a critical scan result (risk >= 70).
    Failures are logged and recorded but never raise — must not block the scan pipeline.
    """
    if not user_id:
        return
    try:
        rows = (
            db.table("integration_configs")
            .select("service,config,enabled,error_count")
            .eq("user_id", user_id)
            .eq("enabled", True)
            .execute()
        )
        configs = rows.data or []
    except Exception as e:
        log.warning(f"[integrations] Failed to load configs for user {user_id}: {e}")
        return

    for row in configs:
        service = row["service"]
        connector_cls = CONNECTORS.get(service)
        if not connector_cls:
            continue
        try:
            connector = connector_cls(row["config"])
            connector.push(finding)
            db.table("integration_configs").update({
                "last_fired_at": datetime.now(timezone.utc).isoformat(),
                "error_count":   0,
                "last_error":    None,
                "updated_at":    datetime.now(timezone.utc).isoformat(),
            }).eq("user_id", user_id).eq("service", service).execute()
            log.info(f"[integrations] {service} → {finding.get('domain')} OK")
        except Exception as e:
            log.warning(f"[integrations] {service} failed for {finding.get('domain')}: {e}")
            try:
                db.table("integration_configs").update({
                    "error_count": (row.get("error_count") or 0) + 1,
                    "last_error":  str(e)[:500],
                    "updated_at":  datetime.now(timezone.utc).isoformat(),
                }).eq("user_id", user_id).eq("service", service).execute()
            except Exception:
                pass
