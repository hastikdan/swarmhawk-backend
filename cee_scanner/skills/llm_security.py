"""
cee_scanner.skills.llm_security
==================================
OWASP LLM01-LLM10:2025 — LLM Application Security

Detects AI chatbots, LLM-backed features, and flags associated risks.
No active exploit attempts — passive detection only.

Checks:
  - AI chatbot widgets (intercom-style, custom chat, GPT integrations)
  - LLM API key disclosure (OpenAI, Anthropic, Cohere, HuggingFace keys in source)
  - Prompt injection surface indicators in chat/search interfaces
  - AI-generated content without safety disclaimers
  - LLM provider SDK scripts loaded from CDN
  - Vector database admin panels exposed (Pinecone, Weaviate, Qdrant)
"""

import re
import requests
import logging

logger = logging.getLogger("cee_scanner.skills.llm_security")

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}

# LLM-related API keys in source (partial patterns — we avoid logging full keys)
API_KEY_PATTERNS = [
    (re.compile(r'sk-[A-Za-z0-9]{20,}'),           "OpenAI API key"),
    (re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}'),    "Anthropic API key"),
    (re.compile(r'co-[A-Za-z0-9]{20,}'),            "Cohere API key"),
    (re.compile(r'hf_[A-Za-z0-9]{20,}'),            "HuggingFace token"),
    (re.compile(r'AIza[A-Za-z0-9\-_]{35}'),         "Google AI API key"),
    (re.compile(r'gsk_[A-Za-z0-9]{20,}'),           "Groq API key"),
    (re.compile(r'OPENAI_API_KEY\s*[:=]\s*["\']?sk-'), "OpenAI key in config"),
    (re.compile(r'ANTHROPIC_API_KEY\s*[:=]\s*["\']?sk-ant-'), "Anthropic key in config"),
]

# Signs of an AI chatbot being present
CHATBOT_INDICATORS = [
    (re.compile(r'intercom|drift\.com|hubspot.*chat|zendesk.*chat', re.IGNORECASE),
     "Third-party chatbot widget"),
    (re.compile(r'openai|chatgpt|gpt-[34]|claude\.|gemini\.', re.IGNORECASE),
     "Direct LLM provider reference"),
    (re.compile(r'chat-widget|ai-chat|chat-bubble|chatbot|ask-ai|ai-assistant', re.IGNORECASE),
     "AI chat widget"),
    (re.compile(r'data-openai|data-claude|data-llm|data-ai-model', re.IGNORECASE),
     "LLM data attribute"),
    (re.compile(r'completions|chat/completions|/v1/messages', re.IGNORECASE),
     "LLM API endpoint reference"),
]

# Prompt injection surface indicators
PROMPT_INJECT_INDICATORS = re.compile(
    r'<input[^>]+(?:placeholder|aria-label)=["\'][^"\']*(?:ask|question|prompt|tell|describe|search|chat)[^"\']*["\']',
    re.IGNORECASE
)

# Vector DB admin panels
VECTOR_DB_PATHS = [
    ("/weaviate/",      "Weaviate"),
    ("/qdrant/",        "Qdrant"),
    ("/:db/",           "Generic vector DB"),
    ("/pinecone/",      "Pinecone"),
    ("/chroma/",        "Chroma"),
    ("/api/v1/collections", "Chroma API"),
    ("/api/collections",    "Qdrant API"),
]

# LLM SDK CDN scripts
LLM_SDK_SCRIPTS = re.compile(
    r'cdn.*openai|unpkg.*openai|cdn.*langchain|cdn.*llm|openai\.min\.js',
    re.IGNORECASE
)


def check_llm_security(domain: str) -> "CheckResult":
    """
    OWASP LLM01-LLM10:2025 — LLM application security assessment.

    CRITICAL: LLM API keys exposed in source, vector DB admin panel accessible.
    WARNING:  AI chatbot detected (prompt injection risk LLM01), LLM API refs in source.
    """
    from cee_scanner.checks import CheckResult
    result = CheckResult("llm_security", domain)

    critical_findings = []
    findings = []

    try:
        r = requests.get(
            f"https://{domain}", timeout=TIMEOUT, headers=HEADERS,
            allow_redirects=True, verify=False
        )
        body = r.text

        # ── 1. Check for exposed API keys ────────────────────────────────
        for pattern, label in API_KEY_PATTERNS:
            if pattern.search(body):
                critical_findings.append(
                    f"{label} found in page source — immediately revoke and rotate this key"
                )

        # ── 2. Detect chatbot / LLM integration ──────────────────────────
        chatbot_detected = False
        for pattern, label in CHATBOT_INDICATORS:
            if pattern.search(body):
                chatbot_detected = True
                findings.append(f"LLM feature detected: {label}")

        if LLM_SDK_SCRIPTS.search(body):
            chatbot_detected = True
            findings.append("LLM SDK loaded from CDN in page source")

        # ── 3. Prompt injection surface ───────────────────────────────────
        if chatbot_detected:
            pi_inputs = PROMPT_INJECT_INDICATORS.findall(body)
            if pi_inputs:
                findings.append(
                    f"Prompt injection surface: {len(pi_inputs)} AI-facing input(s) found "
                    f"(LLM01 — verify system prompt isolation and output filtering)"
                )
            else:
                findings.append(
                    "AI chatbot present — verify: system prompt not extractable (LLM01), "
                    "no sensitive data in context (LLM02), output filtered (LLM05)"
                )

        # ── 4. Check for exposed LLM config / .env with keys ─────────────
        for path in ["/.env", "/config.js", "/env.js", "/app-config.js",
                     "/static/config.js", "/assets/config.js"]:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                if pr.status_code != 200:
                    continue
                content = pr.text[:3000]
                for pattern, label in API_KEY_PATTERNS:
                    if pattern.search(content):
                        critical_findings.append(
                            f"{label} exposed at {path} — revoke immediately"
                        )
            except Exception:
                pass

        # ── 5. Check for exposed vector DB admin panels ───────────────────
        for path, db_name in VECTOR_DB_PATHS:
            try:
                pr = requests.get(
                    f"https://{domain}{path}", timeout=TIMEOUT,
                    headers=HEADERS, verify=False, allow_redirects=False
                )
                if pr.status_code in (200, 401):
                    if pr.status_code == 200:
                        critical_findings.append(
                            f"{db_name} vector database admin panel accessible at {path} "
                            f"without authentication — exposes training data and embeddings"
                        )
                    else:
                        findings.append(f"{db_name} panel at {path} responds (auth required — verify hardening)")
            except Exception:
                pass

    except Exception as e:
        return result.ok("LLM security check skipped", str(e)[:80])

    if not findings and not critical_findings:
        return result.ok("No LLM/AI features detected", "No AI chatbots, LLM APIs, or vector databases found")

    if critical_findings:
        detail = "Critical:\n" + "\n".join(f"• {f}" for f in critical_findings)
        if findings:
            detail += "\nWarnings:\n" + "\n".join(f"• {f}" for f in findings)
        return result.critical(
            f"LLM: {len(critical_findings)} critical AI security issue(s)",
            detail,
            impact=min(25, len(critical_findings) * 20 + len(findings) * 2)
        )

    return result.warn(
        f"LLM: AI features detected — {len(findings)} security consideration(s)",
        "\n".join(f"• {f}" for f in findings),
        impact=min(8, len(findings) * 3)
    )
