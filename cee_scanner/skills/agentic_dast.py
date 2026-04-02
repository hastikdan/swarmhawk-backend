"""
cee_scanner.skills.agentic_dast
================================
Shannon-inspired multi-agent DAST.

Two-phase analysis:

  Phase 1 — Same 82-probe surface scan as dast.py (always runs, no API needed).

  Phase 2 — If ANTHROPIC_API_KEY is set, three parallel Claude agents analyse
             the probe results and surface additional insights:

               Agent 1  Injection Analyst   — SQL, SSTI, XSS, path traversal
               Agent 2  Auth Analyst        — auth flows, session exposure, IDOR
               Agent 3  Config Analyst      — misconfigs, info leakage, chained risks

             Each agent returns JSON:
               [{"severity": "critical|warning", "title": "...", "detail": "..."}]

             Agent findings are merged with probe findings and deduped.

Falls back to probe-only mode (identical behaviour to check_dast) when no API key is set.
"""

import os
import re
import json
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from cee_scanner.skills.dast import (
    DAST_PROBES,
    _check_open_redirect,
    _check_stack_trace,
)

logger = logging.getLogger("cee_scanner.skills.agentic_dast")

TIMEOUT      = 8
REQ_HEADERS  = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}
CLAUDE_MODEL = "claude-haiku-4-5-20251001"


# ─── Phase 1: probe scan ──────────────────────────────────────────────────────

def _run_probes(domain: str) -> tuple[list[str], list[str]]:
    """Run all DAST probes.  Returns (critical_findings, warning_findings)."""
    critical: list[str] = []
    warning:  list[str] = []

    for path, label, severity, confirm_pat in DAST_PROBES:
        try:
            r = requests.get(
                f"https://{domain}{path}",
                timeout=TIMEOUT, headers=REQ_HEADERS,
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
            if path == "/robots.txt":
                hidden = re.findall(r"Disallow:\s*(/[^\s]+)", body)
                hidden = [h for h in hidden if len(h) > 1]
                if hidden:
                    warning.append(
                        f"robots.txt reveals {len(hidden)} hidden path(s): {', '.join(hidden[:5])}"
                    )
                continue
            if path == "/sitemap.xml":
                continue
            (critical if severity == "critical" else warning).append(
                f"{label} ({path})"
            )
        except Exception:
            continue

    if redirect := _check_open_redirect(domain):
        critical.append(redirect)
    if stack := _check_stack_trace(domain):
        warning.append(stack)

    return critical, warning


# ─── Phase 2: Claude agents ───────────────────────────────────────────────────

_AGENTS = [
    {
        "name": "injection",
        "system": (
            "You are an Injection Analyst on a security assessment team. "
            "You receive passive HTTP probe results for a domain — no active exploitation has occurred. "
            "Your job: identify SQL injection vectors, SSTI sinks, XSS surfaces, "
            "path traversal risks, and command injection indicators implied by the "
            "observed exposed endpoints. "
            "Return ONLY a compact JSON array (no prose, no markdown). "
            "Each item: {\"severity\":\"critical|warning\",\"title\":\"short title\","
            "\"detail\":\"1-2 sentence evidence-based explanation\"}. "
            "Return at most 4 items. Return [] if no real evidence exists."
        ),
    },
    {
        "name": "auth",
        "system": (
            "You are an Authentication & Access Control Analyst on a security assessment team. "
            "You receive passive HTTP probe results — no active exploitation has occurred. "
            "Your job: identify authentication bypass opportunities, exposed session management, "
            "default credential surfaces, IDOR indicators, and privilege escalation paths "
            "implied by exposed admin panels, API endpoints, and monitoring interfaces. "
            "Return ONLY a compact JSON array (no prose, no markdown). "
            "Each item: {\"severity\":\"critical|warning\",\"title\":\"short title\","
            "\"detail\":\"1-2 sentence evidence-based explanation\"}. "
            "Return at most 4 items. Return [] if no real evidence exists."
        ),
    },
    {
        "name": "config",
        "system": (
            "You are a Configuration & Exposure Analyst on a security assessment team. "
            "You receive passive HTTP probe results — no active exploitation has occurred. "
            "Your job: assess the combined attack surface, information disclosure severity, "
            "misconfiguration chains (how individual findings combine into higher-severity paths), "
            "and technology stack exposure. Look for patterns like 'API docs + admin panel = "
            "authenticated RCE path' or 'stack trace + Dockerfile = full tech stack recon'. "
            "Return ONLY a compact JSON array (no prose, no markdown). "
            "Each item: {\"severity\":\"critical|warning\",\"title\":\"short title\","
            "\"detail\":\"1-2 sentence evidence-based explanation\"}. "
            "Return at most 4 items. Return [] if no real evidence exists."
        ),
    },
]


def _build_user_prompt(domain: str, critical: list[str], warning: list[str]) -> str:
    lines = [f"Target domain: {domain}", ""]
    if critical:
        lines.append("Critical probe findings:")
        lines.extend(f"  - {f}" for f in critical)
    if warning:
        lines.append("Warning probe findings:")
        lines.extend(f"  - {f}" for f in warning)
    if not critical and not warning:
        lines.append("No probe findings detected.")
    lines += ["", "Analyse these findings and return your JSON array."]
    return "\n".join(lines)


def _call_agent(
    agent: dict, domain: str,
    critical: list[str], warning: list[str],
    api_key: str,
) -> list[dict]:
    """Call one Claude agent synchronously. Returns list of findings."""
    try:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        # Route through Portkey gateway if configured (cost tracking)
        portkey_key = os.getenv("PORTKEY_API_KEY", "")
        if portkey_key:
            headers["x-portkey-api-key"] = portkey_key
            headers["x-portkey-provider"] = "anthropic"
            url = "https://api.portkey.ai/v1/messages"

        payload = {
            "model": CLAUDE_MODEL,
            "max_tokens": 512,
            "system": agent["system"],
            "messages": [
                {"role": "user", "content": _build_user_prompt(domain, critical, warning)}
            ],
        }
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        text = r.json()["content"][0]["text"].strip()

        # Extract JSON array — Claude sometimes wraps in ```json ... ```
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            return json.loads(m.group())
        return []
    except Exception as e:
        logger.debug(f"Agentic DAST agent '{agent['name']}' skipped: {e}")
        return []


def _run_agents(
    domain: str,
    critical: list[str],
    warning: list[str],
    api_key: str,
) -> list[dict]:
    """Run all 3 agents in parallel. Returns merged, deduped findings."""
    all_findings: list[dict] = []
    seen: set[str] = set()

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(_call_agent, ag, domain, critical, warning, api_key): ag
            for ag in _AGENTS
        }
        for fut in as_completed(futures):
            for f in (fut.result() or []):
                title = f.get("title", "").strip()
                if title and title.lower() not in seen:
                    seen.add(title.lower())
                    all_findings.append(f)

    return all_findings


# ─── Result builder ────────────────────────────────────────────────────────────

def _build_check_result(
    domain: str,
    critical: list[str],
    warning: list[str],
    agent_enhanced: bool = False,
) -> "CheckResult":
    from cee_scanner.checks import CheckResult
    res = CheckResult("dast", domain)

    if not critical and not warning:
        return res.ok(
            "DAST: no exposed panels, APIs, or misconfigurations found",
            "No admin panels, API docs, monitoring endpoints, or open redirects detected",
        )

    tag = " [AI-enhanced]" if agent_enhanced else ""
    detail = ""
    if critical:
        detail += "Critical:\n" + "\n".join(f"  • {f}" for f in critical) + "\n"
    if warning:
        detail += "Warnings:\n" + "\n".join(f"  • {f}" for f in warning)

    if critical:
        return res.critical(
            f"DAST: {len(critical)} critical finding(s){tag} — {critical[0]}",
            detail.strip(),
            impact=30,
        )
    return res.warn(
        f"DAST: {len(warning)} finding(s){tag} — {warning[0]}",
        detail.strip(),
        impact=12,
    )


# ─── Public interface ─────────────────────────────────────────────────────────

def check_agentic_dast(domain: str) -> "CheckResult":
    """
    Shannon-inspired multi-agent DAST check.

    Phase 1 (always): run 82-probe passive surface scan.
    Phase 2 (when ANTHROPIC_API_KEY set): 3 parallel Claude agents reason over
    probe results to surface injection vectors, auth weaknesses, and chained risks.
    """
    critical, warning = _run_probes(domain)

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or (not critical and not warning):
        # No API key, or nothing to reason about — return probe results as-is
        return _build_check_result(domain, critical, warning, agent_enhanced=False)

    # Phase 2: enrich with 3 parallel Claude agents
    agent_findings = _run_agents(domain, critical, warning, api_key)
    for f in agent_findings:
        sev   = f.get("severity", "warning")
        title = f.get("title", "").strip()
        dtl   = f.get("detail", "").strip()
        entry = f"{title}" + (f" — {dtl}" if dtl else "")
        if not title:
            continue
        if sev == "critical" and entry not in critical:
            critical.append(entry)
        elif entry not in warning:
            warning.append(entry)

    return _build_check_result(domain, critical, warning, agent_enhanced=True)
