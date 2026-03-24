"""
org_graph.py — SwarmHawk Enterprise Organization Graph Engine
=============================================================

Clusters internet-facing domains from scan_results into organizations,
computes attack graphs (breach paths), identifies choke points and blast
radius, and persists results to the organizations table.

Architecture:
  1. extract_registered_domain()   — eTLD+1 from any domain
  2. cluster_and_upsert_orgs()     — group scan_results by registered_domain
  3. classify_domain_node()        — entry / critical / pivot / safe
  4. compute_breach_paths()        — build attack graph for one org
  5. compute_org_risk_score()      — 0-100 aggregate org risk
  6. compute_org_graph_job()       — main job, called from API or scheduler
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# ── Known multi-part TLDs (eTLD set for registered domain extraction) ─────────
_MULTI_TLDS = {
    "co.uk","org.uk","me.uk","net.uk","ltd.uk","plc.uk","gov.uk","ac.uk",
    "co.jp","ne.jp","or.jp","ac.jp","ad.jp","ed.jp","go.jp","gr.jp","lg.jp",
    "com.au","net.au","org.au","edu.au","gov.au","asn.au","id.au",
    "co.nz","net.nz","org.nz","govt.nz","ac.nz","school.nz",
    "co.za","org.za","net.za","edu.za","gov.za",
    "com.br","net.br","org.br","gov.br","edu.br","co.br",
    "com.pl","org.pl","net.pl","co.pl","edu.pl","gov.pl",
    "com.cz","co.cz","org.cz","net.cz",
    "com.sk","co.sk","org.sk","net.sk",
    "com.ro","co.ro","org.ro","net.ro",
    "com.hu","co.hu","org.hu","net.hu",
    "com.bg","org.bg","net.bg","co.bg",
    "com.hr","from.hr","iz.hr","name.hr",
    "com.si","org.si","net.si","co.si",
    "com.rs","org.rs","net.rs","co.rs","edu.rs","gov.rs",
    "com.ua","org.ua","net.ua","co.ua","edu.ua","gov.ua",
    "com.ee","org.ee","co.ee","net.ee",
    "com.lt","org.lt","co.lt","net.lt",
    "com.lv","org.lv","co.lv","net.lv",
    "com.tr","org.tr","net.tr","co.tr","edu.tr","gov.tr",
    "com.mx","org.mx","net.mx","co.mx","gob.mx",
    "com.ar","org.ar","net.ar","co.ar","gov.ar",
    "com.sg","org.sg","net.sg","edu.sg","gov.sg",
    "com.hk","org.hk","net.hk","gov.hk","edu.hk",
}

# Critical-asset keywords in domain names
_CRITICAL_KEYWORDS = {
    "admin","login","portal","erp","crm","vpn","remote","rdp","panel",
    "manage","secure","internal","private","intranet","corp","hr","payroll",
    "finance","billing","payment","api","gateway","dashboard","console",
    "backoffice","back-office","helpdesk","jira","confluence","gitlab",
    "jenkins","kibana","grafana","prometheus","vault","secrets","db",
    "database","mongo","mysql","postgres","elastic","redis","backup",
}

_DOMAIN_RE = re.compile(r'^[a-z0-9][a-z0-9\-\.]{1,253}[a-z0-9]$')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_db():
    """Import get_db from main pipeline module."""
    try:
        from pipeline import _get_db as pgdb
        return pgdb()
    except ImportError:
        from main import get_db
        return get_db()


def extract_registered_domain(domain: str) -> str:
    """
    Extract the registered domain (eTLD+1) from any FQDN.

    Examples:
      vpn.acme.com       -> acme.com
      mail.acme.co.uk    -> acme.co.uk
      api.startup.io     -> startup.io
      example.com        -> example.com
    """
    domain = domain.lower().strip().rstrip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain

    # Check if last two parts form a known multi-TLD
    two = ".".join(parts[-2:])
    if two in _MULTI_TLDS:
        # registered domain = parts[-3] + "." + two (if enough parts)
        if len(parts) >= 3:
            return ".".join(parts[-3:])
        return domain  # already at apex

    # Default: last two parts
    return ".".join(parts[-2:])


def classify_domain_node(record: dict) -> str:
    """
    Classify a domain record as one of:
      entry    — exploitable external entry point for an attacker
      critical — high-value target (admin panels, ERP, business-critical)
      pivot    — intermediate stepping stone (exposed, some risk)
      safe     — low risk
    """
    domain = (record.get("domain") or "").lower()
    max_cvss = float(record.get("max_cvss") or 0)
    blacklisted = record.get("blacklisted") or False
    urlhaus = record.get("urlhaus_status")
    ip_rep = (record.get("ip_reputation") or "").lower()
    dmarc = (record.get("dmarc_status") or "").lower()
    spf = (record.get("spf_status") or "").lower()
    risk_score = int(record.get("risk_score") or 0)
    checks = record.get("checks") or []
    waf = record.get("waf_detected") or False

    # ── Entry point: has exploitable CVE, blacklisted, or phishing vector ────
    is_entry = (
        max_cvss >= 7.0
        or blacklisted
        or urlhaus not in (None, "", "clean")
        or ip_rep in ("critical", "high", "malicious")
        or (dmarc == "missing" and spf == "missing")  # phishing entry vector
    )
    if is_entry:
        return "entry"

    # ── Critical asset: contains sensitive keywords or has DAST/admin findings
    domain_label = domain.split(".")[0]  # subdomain label
    if any(kw in domain_label for kw in _CRITICAL_KEYWORDS):
        return "critical"

    # Check DAST results in checks array for critical findings
    for check in checks:
        if not isinstance(check, dict):
            continue
        title = (check.get("title") or "").lower()
        detail = (check.get("detail") or "").lower()
        status = (check.get("status") or "").lower()
        if status in ("critical", "warning") and any(
            kw in title or kw in detail
            for kw in ("admin", "panel", "swagger", "graphql", "actuator",
                       "phpmyadmin", "login", "dashboard", "console")
        ):
            return "critical"

    # ── Pivot: reachable with moderate risk ───────────────────────────────────
    if risk_score >= 30 and not waf:
        return "pivot"

    return "safe"


# ── MITRE ATT&CK technique mapping ───────────────────────────────────────────

def _mitre_technique(source_type: str, target_type: str, record: dict) -> tuple[str, str]:
    """Return (technique_id, label) for an attack graph edge."""
    max_cvss = float(record.get("max_cvss") or 0)
    blacklisted = record.get("blacklisted") or False
    dmarc = (record.get("dmarc_status") or "").lower()
    spf = (record.get("spf_status") or "").lower()

    if source_type == "entry":
        if max_cvss >= 7.0:
            return ("T1190", "Exploit Public-Facing Application")
        if blacklisted:
            return ("T1584", "Compromise Infrastructure")
        if dmarc == "missing" and spf == "missing":
            return ("T1566", "Phishing / Email Spoofing")
    if source_type == "pivot":
        return ("T1021", "Remote Services / Lateral Movement")
    if target_type == "critical":
        return ("T1078", "Valid Accounts / Credential Access")
    return ("T1071", "Application Layer Protocol")


# ── Breach path computation ───────────────────────────────────────────────────

def compute_breach_paths(org_domains: list[dict]) -> dict:
    """
    Build the complete attack graph for one organization.

    Returns:
    {
      nodes: [{id, domain, type, risk_score, max_cvss, techniques, label, cve_count}],
      edges: [{source, target, technique, label}],
      paths: [[node_id, ...], ...],   # each = one entry→critical route
      choke_points: [node_id, ...],   # sorted by paths_through desc
      blast_radius: {node_id: int},   # critical assets reachable from node
      stats: {entry_count, critical_count, pivot_count, total_paths, top_risk_domain}
    }
    """
    if not org_domains:
        return {"nodes": [], "edges": [], "paths": [], "choke_points": [],
                "blast_radius": {}, "stats": {}}

    # 1. Classify nodes
    nodes = []
    node_by_domain = {}
    for rec in org_domains:
        ntype = classify_domain_node(rec)
        cves = rec.get("cves") or []
        node = {
            "id":          rec["domain"],
            "domain":      rec["domain"],
            "type":        ntype,
            "risk_score":  int(rec.get("risk_score") or 0),
            "max_cvss":    float(rec.get("max_cvss") or 0),
            "cve_count":   len(cves) if isinstance(cves, list) else 0,
            "label":       rec["domain"],
            "blacklisted": bool(rec.get("blacklisted")),
            "dmarc":       rec.get("dmarc_status"),
            "waf":         bool(rec.get("waf_detected")),
            "priority":    rec.get("priority", "INFO"),
        }
        nodes.append(node)
        node_by_domain[rec["domain"]] = node

    entries   = [n for n in nodes if n["type"] == "entry"]
    criticals = [n for n in nodes if n["type"] == "critical"]
    pivots    = [n for n in nodes if n["type"] == "pivot"]

    # 2. Build edges
    edges = []
    edge_set = set()

    def add_edge(src_id, tgt_id, technique, label):
        key = (src_id, tgt_id)
        if key not in edge_set:
            edge_set.add(key)
            edges.append({"source": src_id, "target": tgt_id,
                          "technique": technique, "label": label})

    # entry → pivot
    for e in entries:
        rec = next((r for r in org_domains if r["domain"] == e["id"]), {})
        tech, lbl = _mitre_technique("entry", "pivot", rec)
        for p in pivots:
            add_edge(e["id"], p["id"], tech, lbl)

    # entry → critical (direct)
    for e in entries:
        rec = next((r for r in org_domains if r["domain"] == e["id"]), {})
        tech, lbl = _mitre_technique("entry", "critical", rec)
        for c in criticals:
            add_edge(e["id"], c["id"], tech, lbl)

    # pivot → critical
    for p in pivots:
        rec = next((r for r in org_domains if r["domain"] == p["id"]), {})
        tech, lbl = _mitre_technique("pivot", "critical", rec)
        for c in criticals:
            add_edge(p["id"], c["id"], tech, lbl)

    # entry → entry (chaining multiple entry points)
    if len(entries) > 1:
        for i, e1 in enumerate(entries[:-1]):
            rec = next((r for r in org_domains if r["domain"] == e1["id"]), {})
            tech, lbl = _mitre_technique("entry", "entry", rec)
            for e2 in entries[i+1:]:
                add_edge(e1["id"], e2["id"], tech, lbl)

    # 3. Enumerate paths (entry → [pivot?] → critical), max depth 4
    paths = []
    MAX_PATHS = 100

    def dfs(current_id, path, visited):
        if len(paths) >= MAX_PATHS:
            return
        current_node = node_by_domain.get(current_id)
        if not current_node:
            return
        if current_node["type"] == "critical" and len(path) > 1:
            paths.append(list(path))
            return
        if len(path) >= 4:  # max depth
            return
        for edge in edges:
            if edge["source"] == current_id and edge["target"] not in visited:
                visited.add(edge["target"])
                path.append(edge["target"])
                dfs(edge["target"], path, visited)
                path.pop()
                visited.discard(edge["target"])

    for entry in entries:
        if len(paths) >= MAX_PATHS:
            break
        dfs(entry["id"], [entry["id"]], {entry["id"]})

    # 4. Choke points — nodes appearing in the most paths (excluding start/end)
    path_count: dict[str, int] = {}
    for path in paths:
        for node_id in path[1:-1]:  # exclude entry and final critical
            path_count[node_id] = path_count.get(node_id, 0) + 1

    choke_points = sorted(path_count.keys(), key=lambda x: path_count[x], reverse=True)

    # Also count how many paths each node appears in overall
    all_path_count: dict[str, int] = {}
    for path in paths:
        for node_id in path:
            all_path_count[node_id] = all_path_count.get(node_id, 0) + 1

    for node in nodes:
        node["paths_through"] = all_path_count.get(node["id"], 0)
        node["is_choke_point"] = node["id"] in choke_points[:5]  # top 5

    # 5. Blast radius — critical assets reachable from each node
    blast_radius: dict[str, int] = {}
    for node in nodes:
        reachable_criticals = set()
        for path in paths:
            if node["id"] in path:
                idx = path.index(node["id"])
                # count criticals after this node in this path
                for subsequent in path[idx+1:]:
                    sn = node_by_domain.get(subsequent)
                    if sn and sn["type"] == "critical":
                        reachable_criticals.add(subsequent)
        blast_radius[node["id"]] = len(reachable_criticals)

    # 6. Stats
    top_risk = max(org_domains, key=lambda r: float(r.get("max_cvss") or 0), default={})
    stats = {
        "entry_count":    len(entries),
        "critical_count": len(criticals),
        "pivot_count":    len(pivots),
        "safe_count":     len([n for n in nodes if n["type"] == "safe"]),
        "total_paths":    len(paths),
        "choke_point_count": len(choke_points),
        "top_risk_domain": top_risk.get("domain", ""),
        "top_cvss":        float(top_risk.get("max_cvss") or 0),
    }

    return {
        "nodes":        nodes,
        "edges":        edges,
        "paths":        paths,
        "choke_points": choke_points[:10],
        "blast_radius": blast_radius,
        "stats":        stats,
    }


# ── Organization risk score ───────────────────────────────────────────────────

def compute_org_risk_score(org_domains: list[dict], breach_paths: dict) -> int:
    """
    Aggregate 0-100 risk score for an organization.
    Weighted components:
      30% — highest individual domain risk_score
      25% — entry point density (entry_count / total_domains)
      25% — critical asset exposure (critical_assets reachable)
      20% — total attack paths (capped at 50)
    """
    if not org_domains:
        return 0

    stats = breach_paths.get("stats", {})
    total = len(org_domains)

    max_domain_risk  = max((int(r.get("risk_score") or 0) for r in org_domains), default=0)
    entry_count      = stats.get("entry_count", 0)
    critical_count   = stats.get("critical_count", 0)
    total_paths      = min(stats.get("total_paths", 0), 50)

    entry_density    = (entry_count / total) if total > 0 else 0
    crit_exposure    = min(critical_count / max(total, 1) * 2, 1.0)  # normalize to 1
    path_score       = total_paths / 50

    score = (
        max_domain_risk * 0.30
        + entry_density   * 100 * 0.25
        + crit_exposure   * 100 * 0.25
        + path_score      * 100 * 0.20
    )
    return min(100, max(0, round(score)))


# ── Cluster and upsert organizations ─────────────────────────────────────────

def cluster_and_upsert_organizations(db=None, batch_size: int = 5000) -> dict:
    """
    Read all scan_results, group by registered_domain, upsert organizations table.
    Also backfills scan_results.registered_domain column.

    Returns: {orgs_created, orgs_updated, domains_tagged, total_processed}
    """
    db = db or _get_db()
    stats = {"orgs_created": 0, "orgs_updated": 0, "domains_tagged": 0, "total_processed": 0}

    # Fetch all domains (select minimal columns for clustering)
    log.info("[org_graph] fetching all scan_results for clustering...")
    offset = 0
    all_records: list[dict] = []

    while True:
        try:
            batch = db.table("scan_results").select(
                "domain,tld,country,risk_score,max_cvss,blacklisted,urlhaus_status,"
                "ip_reputation,dmarc_status,spf_status,waf_detected,checks,cves,"
                "priority,registered_domain,registrar,domain_age_days,scan_tier"
            ).range(offset, offset + batch_size - 1).execute()
            rows = batch.data or []
            if not rows:
                break
            all_records.extend(rows)
            offset += len(rows)
            log.info(f"[org_graph] fetched {offset:,} records...")
            if len(rows) < batch_size:
                break
        except Exception as e:
            log.error(f"[org_graph] fetch error at offset {offset}: {e}")
            break

    stats["total_processed"] = len(all_records)
    log.info(f"[org_graph] total domains to cluster: {len(all_records):,}")

    # Group by registered_domain
    clusters: dict[str, list[dict]] = {}
    domain_to_reg: dict[str, str] = {}

    for rec in all_records:
        domain = rec.get("domain", "")
        if not domain:
            continue
        reg = extract_registered_domain(domain)
        rec["_registered_domain"] = reg
        domain_to_reg[domain] = reg
        clusters.setdefault(reg, []).append(rec)

    log.info(f"[org_graph] {len(clusters):,} organizations identified")

    # Backfill registered_domain in scan_results (batch updates)
    domains_needing_update = [
        domain for domain, rec in zip(domain_to_reg.keys(), all_records)
        if not rec.get("registered_domain")
    ]
    log.info(f"[org_graph] backfilling registered_domain for {len(domains_needing_update):,} domains")

    for i in range(0, len(all_records), 200):
        chunk = all_records[i:i + 200]
        for rec in chunk:
            reg = rec.get("_registered_domain")
            if reg and not rec.get("registered_domain"):
                try:
                    db.table("scan_results").update(
                        {"registered_domain": reg}
                    ).eq("domain", rec["domain"]).execute()
                    stats["domains_tagged"] += 1
                except Exception:
                    pass

    # Compute breach paths and upsert organizations
    for reg_domain, domains in clusters.items():
        try:
            breach = compute_breach_paths(domains)
            risk   = compute_org_risk_score(domains, breach)
            s      = breach.get("stats", {})

            # Infer country from most common country in cluster
            countries = [r.get("country") for r in domains if r.get("country")]
            country = max(set(countries), key=countries.count) if countries else None

            # Infer name from registered domain (capitalize apex)
            name = reg_domain.split(".")[0].replace("-", " ").title()

            org_row = {
                "registered_domain": reg_domain,
                "name":              name,
                "domain_count":      len(domains),
                "org_risk_score":    risk,
                "entry_points":      s.get("entry_count", 0),
                "critical_assets":   s.get("critical_count", 0),
                "choke_points":      len(breach.get("choke_points", [])),
                "attack_paths":      s.get("total_paths", 0),
                "asset_graph":       breach,
                "country":           country,
                "last_computed":     datetime.now(timezone.utc).isoformat(),
            }

            # Check if org exists
            existing = db.table("organizations").select("id").eq(
                "registered_domain", reg_domain
            ).execute()

            if existing.data:
                db.table("organizations").update(org_row).eq(
                    "registered_domain", reg_domain
                ).execute()
                stats["orgs_updated"] += 1
            else:
                db.table("organizations").insert(org_row).execute()
                stats["orgs_created"] += 1

        except Exception as e:
            log.warning(f"[org_graph] failed to process org {reg_domain}: {e}")

    log.info(f"[org_graph] clustering done — {stats}")
    return stats


# ── Main compute job ──────────────────────────────────────────────────────────

def compute_org_graph_job(org_id: str = None, db=None) -> dict:
    """
    Main entry point for org graph computation.

    If org_id given: recompute just that organization.
    If None: full clustering pass across all scan_results.
    """
    db = db or _get_db()

    if org_id:
        # Recompute single org
        log.info(f"[org_graph] recomputing single org: {org_id}")
        org_row = db.table("organizations").select("registered_domain").eq("id", org_id).execute()
        if not org_row.data:
            return {"error": f"org {org_id} not found"}

        reg = org_row.data[0]["registered_domain"]
        domains = db.table("scan_results").select(
            "domain,tld,country,risk_score,max_cvss,blacklisted,urlhaus_status,"
            "ip_reputation,dmarc_status,spf_status,waf_detected,checks,cves,"
            "priority,registrar,domain_age_days,scan_tier"
        ).eq("registered_domain", reg).execute().data or []

        if not domains:
            return {"error": f"no domains found for {reg}"}

        breach = compute_breach_paths(domains)
        risk   = compute_org_risk_score(domains, breach)
        s      = breach.get("stats", {})

        db.table("organizations").update({
            "domain_count":   len(domains),
            "org_risk_score": risk,
            "entry_points":   s.get("entry_count", 0),
            "critical_assets":s.get("critical_count", 0),
            "choke_points":   len(breach.get("choke_points", [])),
            "attack_paths":   s.get("total_paths", 0),
            "asset_graph":    breach,
            "last_computed":  datetime.now(timezone.utc).isoformat(),
        }).eq("id", org_id).execute()

        log.info(f"[org_graph] recomputed {reg}: risk={risk}, paths={s.get('total_paths',0)}")
        return {"org_id": org_id, "registered_domain": reg, "risk": risk,
                "paths": s.get("total_paths", 0), "status": "recomputed"}

    # Full clustering job
    log.info("[org_graph] starting full org graph computation")

    # Log job start
    try:
        log_row = db.table("org_compute_log").insert({
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
        log_id = log_row.data[0]["id"] if log_row.data else None
    except Exception:
        log_id = None

    result = cluster_and_upsert_organizations(db=db)

    # Update log
    if log_id:
        try:
            db.table("org_compute_log").update({
                "finished_at":    datetime.now(timezone.utc).isoformat(),
                "orgs_created":   result.get("orgs_created", 0),
                "orgs_updated":   result.get("orgs_updated", 0),
                "domains_tagged": result.get("domains_tagged", 0),
                "total_processed":result.get("total_processed", 0),
                "status":         "completed",
            }).eq("id", log_id).execute()
        except Exception:
            pass

    log.info(f"[org_graph] full job complete: {result}")
    return result
