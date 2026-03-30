"""
SwarmHawk XDR & SIEM Integration Connectors
============================================
Push scan findings to 9 external security platforms.
All connectors follow the BaseConnector interface:
  - push(finding)  → bool   (fire-and-forget, raises on failure)
  - test()         → dict   ({ok: bool, message: str})

Async dispatcher: fire_integrations_sync(finding, user_id, db)
  Called from pipeline.upsert_scan_result for risk_score >= 70.
"""

import os
import json
import hmac
import hashlib
import base64
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Deterministic UUID namespace for STIX object IDs
_UUID_NS = uuid.UUID("8f1e1e1e-1e1e-1e1e-1e1e-1e1e1e1e1e1e")


def _uuid4() -> str:
    return str(uuid.uuid4())


def _uuid5(namespace: uuid.UUID, name: str) -> str:
    return str(uuid.uuid5(namespace, name))


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

    def _normalize(self, f: dict) -> dict:
        """Common normalized payload shared by all connectors."""
        return {
            "domain":          f.get("domain", ""),
            "risk_score":      f.get("risk_score", 0),
            "max_cvss":        float(f.get("max_cvss") or 0),
            "priority":        f.get("priority", "INFO"),
            "critical":        f.get("critical", 0),
            "warnings":        f.get("warnings", 0),
            "country":         f.get("country", ""),
            "spf_status":      f.get("spf_status", ""),
            "dmarc_status":    f.get("dmarc_status", ""),
            "blacklisted":     bool(f.get("blacklisted", False)),
            "waf_detected":    bool(f.get("waf_detected", False)),
            "last_scanned_at": f.get("last_scanned_at") or datetime.now(timezone.utc).isoformat(),
            "source":          "swarmhawk",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Splunk SIEM — HTTP Event Collector (HEC)
# Config keys: hec_url, hec_token, index (optional, default "main")
# ─────────────────────────────────────────────────────────────────────────────

class SplunkConnector(BaseConnector):
    SERVICE = "splunk"

    def _hec_url(self) -> str:
        return self.config["hec_url"].rstrip("/") + "/services/collector/event"

    def push(self, finding: dict) -> bool:
        payload = {
            "time":       time.time(),
            "source":     "swarmhawk",
            "sourcetype": "swarmhawk:scan",
            "index":      self.config.get("index", "main"),
            "event":      self._normalize(finding),
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
            self.push({
                "domain": "test.swarmhawk.com", "risk_score": 0,
                "max_cvss": 0.0, "priority": "INFO",
            })
            return {"ok": True, "message": "Test event delivered to Splunk HEC"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Sentinel — Azure Monitor Log Analytics
# Config keys: workspace_id, shared_key, log_type (default "SwarmHawk")
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

    def push(self, finding: dict) -> bool:
        workspace_id = self.config["workspace_id"]
        log_type = self.config.get("log_type", "SwarmHawk")
        body = json.dumps([self._normalize(finding)])
        body_bytes = body.encode("utf-8")
        rfc1123 = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        resp = httpx.post(
            f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            headers={
                "Authorization":       self._shared_key_signature(rfc1123, len(body_bytes)),
                "Content-Type":        "application/json",
                "Log-Type":            log_type,
                "x-ms-date":           rfc1123,
                "time-generated-field": "last_scanned_at",
            },
            content=body_bytes,
            timeout=15,
        )
        resp.raise_for_status()
        return True

    def test(self) -> dict:
        try:
            self.push({
                "domain": "test.swarmhawk.com", "risk_score": 0,
                "max_cvss": 0.0, "priority": "INFO",
                "last_scanned_at": datetime.now(timezone.utc).isoformat(),
            })
            return {"ok": True, "message": "Log sent to Microsoft Sentinel workspace"}
        except Exception as e:
            return {"ok": False, "message": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# CrowdStrike Falcon — OAuth2 + IOC push
# Config keys: client_id, client_secret, base_url (optional)
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
        token = self._get_token()
        cvss = float(finding.get("max_cvss") or 0)
        severity = "HIGH" if cvss >= 7 else "MEDIUM"
        resp = httpx.post(
            f"{self._base()}/iocs/entities/iocs/v1",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "indicators": [{
                    "type":        "domain",
                    "value":       finding["domain"],
                    "action":      "detect",
                    "severity":    severity,
                    "platforms":   ["windows", "mac", "linux"],
                    "description": (
                        f"SwarmHawk EASM: risk={finding.get('risk_score', 0)}, "
                        f"cvss={cvss}, priority={finding.get('priority', 'INFO')}"
                    ),
                    "source":      "SwarmHawk",
                    "tags":        ["swarmhawk", "easm"],
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
# Config keys: api_url, api_key, company_id
# ─────────────────────────────────────────────────────────────────────────────

class GravityZoneConnector(BaseConnector):
    SERVICE = "gravityzone"

    def _api(self) -> str:
        return self.config.get("api_url", "https://cloudgz.gravityzone.bitdefender.com").rstrip("/")

    def push(self, finding: dict) -> bool:
        resp = httpx.post(
            f"{self._api()}/api/v1.0/jsonrpc/push",
            auth=(self.config["api_key"], ""),
            json={
                "id":      "swarmhawk-push",
                "jsonrpc": "2.0",
                "method":  "createCustomRule",
                "params": {
                    "companyId": self.config.get("company_id", ""),
                    "rule": {
                        "name":        f"SwarmHawk: {finding['domain']}",
                        "type":        "domain",
                        "value":       finding["domain"],
                        "description": (
                            f"Risk score: {finding.get('risk_score', 0)}, "
                            f"CVSS: {finding.get('max_cvss', 0)}"
                        ),
                        "action":      "block",
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
# Config keys: api_key, api_key_id, fqdn
# ─────────────────────────────────────────────────────────────────────────────

class CortexConnector(BaseConnector):
    SERVICE = "cortex"

    def _auth_headers(self) -> dict:
        import secrets as _s
        nonce = _s.token_hex(16)
        ts = str(int(time.time() * 1000))
        auth_hash = hashlib.sha256(
            f"{self.config['api_key']}{nonce}{ts}".encode()
        ).hexdigest()
        return {
            "x-xdr-auth-id":  str(self.config["api_key_id"]),
            "x-xdr-nonce":    nonce,
            "x-xdr-timestamp": ts,
            "Authorization":  auth_hash,
            "Content-Type":   "application/json",
        }

    def push(self, finding: dict) -> bool:
        cvss = float(finding.get("max_cvss") or 0)
        resp = httpx.post(
            f"https://api-{self.config['fqdn']}/public_api/v1/alerts/insert_external_event/",
            headers=self._auth_headers(),
            json={
                "request_data": {
                    "alerts": [{
                        "product":          "SwarmHawk",
                        "vendor":           "SwarmHawk",
                        "local_ip":         "",
                        "local_port":       0,
                        "remote_ip":        "",
                        "remote_port":      0,
                        "event_timestamp":  int(time.time() * 1000),
                        "severity":         "HIGH" if cvss >= 7 else "MEDIUM",
                        "alert_name":       f"Domain Risk: {finding['domain']}",
                        "alert_description": (
                            f"SwarmHawk detected {finding['domain']} with risk score "
                            f"{finding.get('risk_score', 0)} and CVSS {cvss}"
                        ),
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
# Jira — Create issues for critical findings
# Config keys: base_url, email, api_token, project_key, issue_type (default "Bug")
# ─────────────────────────────────────────────────────────────────────────────

class JiraConnector(BaseConnector):
    SERVICE = "jira"

    _PRIORITY_MAP = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Lowest"}

    def _auth(self) -> str:
        return base64.b64encode(
            f"{self.config['email']}:{self.config['api_token']}".encode()
        ).decode()

    def push(self, finding: dict) -> bool:
        # Only create tickets for genuinely risky findings
        if finding.get("risk_score", 0) < 70 and float(finding.get("max_cvss") or 0) < 7.0:
            return False

        priority = finding.get("priority", "INFO")
        resp = httpx.post(
            f"{self.config['base_url'].rstrip('/')}/rest/api/3/issue",
            headers={"Authorization": f"Basic {self._auth()}", "Content-Type": "application/json"},
            json={
                "fields": {
                    "project":     {"key": self.config["project_key"]},
                    "summary":     f"[SwarmHawk] {finding['domain']} — Risk {finding.get('risk_score', 0)}/100",
                    "description": {
                        "type": "doc", "version": 1,
                        "content": [{
                            "type": "paragraph",
                            "content": [{"type": "text", "text": "\n".join([
                                f"Domain: {finding['domain']}",
                                f"Risk Score: {finding.get('risk_score', 0)}/100",
                                f"Max CVSS: {finding.get('max_cvss', 0)}",
                                f"Priority: {priority}",
                                f"Country: {finding.get('country', '')}",
                                f"SPF: {finding.get('spf_status', '')}",
                                f"DMARC: {finding.get('dmarc_status', '')}",
                                f"Blacklisted: {finding.get('blacklisted', False)}",
                                f"Source: SwarmHawk EASM",
                            ])}],
                        }],
                    },
                    "issuetype":   {"name": self.config.get("issue_type", "Bug")},
                    "priority":    {"name": self._PRIORITY_MAP.get(priority, "Medium")},
                    "labels":      ["swarmhawk", "security", "easm"],
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
# ServiceNow — Create incidents
# Config keys: instance, username, password, table (default "incident")
# ─────────────────────────────────────────────────────────────────────────────

class ServiceNowConnector(BaseConnector):
    SERVICE = "servicenow"

    _URGENCY  = {"CRITICAL": "1", "HIGH": "1", "MEDIUM": "2", "LOW": "3", "INFO": "3"}
    _IMPACT   = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "2", "LOW": "3", "INFO": "3"}

    def push(self, finding: dict) -> bool:
        priority = finding.get("priority", "INFO")
        resp = httpx.post(
            f"https://{self.config['instance']}.service-now.com/api/now/table/{self.config.get('table', 'incident')}",
            auth=(self.config["username"], self.config["password"]),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={
                "short_description": (
                    f"[SwarmHawk] {finding['domain']} — Risk {finding.get('risk_score', 0)}/100"
                ),
                "description": "\n".join([
                    f"Domain: {finding['domain']}",
                    f"Risk Score: {finding.get('risk_score', 0)}/100",
                    f"Max CVSS: {finding.get('max_cvss', 0)}",
                    f"Priority: {priority}",
                    f"Country: {finding.get('country', '')}",
                    f"SPF: {finding.get('spf_status', '')}",
                    f"DMARC: {finding.get('dmarc_status', '')}",
                    f"Blacklisted: {finding.get('blacklisted', False)}",
                    "Source: SwarmHawk EASM",
                ]),
                "category":    "Security",
                "subcategory": "External Attack Surface",
                "urgency":     self._URGENCY.get(priority, "2"),
                "impact":      self._IMPACT.get(priority, "2"),
                "caller_id":   "SwarmHawk",
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
# Generic Webhook — HMAC-SHA256 signed POST
# Config keys: url, secret (optional, for X-SwarmHawk-Signature header)
# ─────────────────────────────────────────────────────────────────────────────

class WebhookConnector(BaseConnector):
    SERVICE = "webhook"

    def push(self, finding: dict) -> bool:
        payload = {
            "event":             "scan.completed",
            "domain":            finding.get("domain", ""),
            "risk_score":        finding.get("risk_score", 0),
            "max_cvss":          float(finding.get("max_cvss") or 0),
            "priority":          finding.get("priority", "INFO"),
            "critical_findings": finding.get("critical", 0),
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        }
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        secret = self.config.get("secret", "")
        if secret:
            sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-SwarmHawk-Signature"] = f"sha256={sig}"

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
# STIX/TAXII 2.1 — Serve findings as threat intelligence feed
# Config keys: enabled (no external push; findings served via /taxii endpoint)
# ─────────────────────────────────────────────────────────────────────────────

class STIXConnector(BaseConnector):
    SERVICE = "stix"

    def push(self, finding: dict) -> bool:
        # STIX doesn't push to external endpoints — findings are served via /taxii
        return True

    def test(self) -> dict:
        return {"ok": True, "message": "STIX/TAXII 2.1 feed active at /taxii/collections/swarmhawk/objects/"}

    @staticmethod
    def build_bundle(findings: list) -> dict:
        """Convert scan_results rows to a STIX 2.1 bundle."""
        objects: list = []
        now = datetime.now(timezone.utc).isoformat()

        for f in findings:
            domain = f.get("domain", "")
            if not domain:
                continue

            domain_stix_id = f"domain-name--{_uuid5(_UUID_NS, domain)}"
            objects.append({
                "type":         "domain-name",
                "spec_version": "2.1",
                "id":           domain_stix_id,
                "value":        domain,
                "created":      f.get("created_at", now),
                "modified":     f.get("last_scanned_at", now),
            })

            cves = f.get("cves") or []
            if isinstance(cves, str):
                try:
                    cves = json.loads(cves)
                except Exception:
                    cves = []

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
                    "id":                f"relationship--{_uuid5(_UUID_NS, domain_stix_id + vuln_id)}",
                    "relationship_type": "has",
                    "source_ref":        domain_stix_id,
                    "target_ref":        vuln_id,
                    "created":           now,
                    "modified":          now,
                })

        return {
            "type":         "bundle",
            "id":           f"bundle--{_uuid4()}",
            "spec_version": "2.1",
            "objects":      objects,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Connector registry
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
    "splunk":       {"name": "Splunk SIEM",              "logo": "📊", "fields": ["hec_url", "hec_token", "index"]},
    "sentinel":     {"name": "Microsoft Sentinel",       "logo": "🔵", "fields": ["workspace_id", "shared_key", "log_type"]},
    "crowdstrike":  {"name": "CrowdStrike Falcon",       "logo": "🦅", "fields": ["client_id", "client_secret", "base_url"]},
    "gravityzone":  {"name": "Bitdefender GravityZone",  "logo": "🛡️", "fields": ["api_url", "api_key", "company_id"]},
    "cortex":       {"name": "Palo Alto Cortex XDR",     "logo": "🟠", "fields": ["api_key", "api_key_id", "fqdn"]},
    "jira":         {"name": "Jira",                     "logo": "🎫", "fields": ["base_url", "email", "api_token", "project_key", "issue_type"]},
    "servicenow":   {"name": "ServiceNow",               "logo": "🎫", "fields": ["instance", "username", "password", "table"]},
    "webhook":      {"name": "Webhook / REST API",        "logo": "📡", "fields": ["url", "secret"]},
    "stix":         {"name": "STIX / TAXII 2.1",         "logo": "⚡", "fields": []},
}


# ─────────────────────────────────────────────────────────────────────────────
# Async dispatcher — called from pipeline after critical scan results
# ─────────────────────────────────────────────────────────────────────────────

def fire_integrations_sync(finding: dict, user_id: str, db) -> None:
    """Fire all enabled integrations for a user.

    Called synchronously from pipeline.upsert_scan_result when risk_score >= 70.
    Failures are logged and recorded but never raise — they must not block scans.
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
