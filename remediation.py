# remediation.py
"""
Actionable mitigation guidance (Strix-style).

Turns findings into concrete, framework-aligned remediation steps. Guidance is
keyed to OWASP Top 10 for LLM Applications (2025) categories so a report can tell
an engineering team not just *what broke* but *how to fix it*.

Fully deterministic — no LLM calls — so it is fast, offline, and testable.
"""

from attack_taxonomy import ATTACK_TECHNIQUES, OWASP_LLM_2025


# Remediation playbook, keyed by OWASP LLM Top 10 (2025) category.
REMEDIATIONS = {
    "LLM01:2025": {
        "title": "Prompt Injection",
        "summary": "Untrusted input altered the model's behavior or overrode "
                   "system instructions.",
        "controls": [
            "Separate trusted instructions from untrusted input using structured "
            "delimiters, and treat all user/tool/retrieved content as untrusted.",
            "Constrain behavior with allow-listed output schemas and strict tool "
            "input validation rather than relying on prompt wording alone.",
            "Apply least-privilege to any tools the model can call; require "
            "human approval for irreversible actions.",
            "Add an independent input/output moderation layer (classifier or "
            "guardrail) in front of the model.",
        ],
        "references": ["OWASP LLM01:2025", "MITRE ATLAS AML.T0051"],
    },
    "LLM02:2025": {
        "title": "Sensitive Information Disclosure",
        "summary": "The model leaked training data, secrets, or private context.",
        "controls": [
            "Never place secrets or PII in the system prompt or retrievable "
            "context; fetch them out-of-band with proper access control.",
            "Scrub and minimize context passed to the model; apply data-loss "
            "prevention on outputs.",
            "Strip or sandbox model-generated URLs, markdown images, and outbound "
            "requests before rendering — a crafted link is a zero-click "
            "exfiltration channel in agent/browser contexts.",
            "Fine-tune or instruct against verbatim reproduction of sensitive "
            "or copyrighted content.",
        ],
        "references": ["OWASP LLM02:2025", "MITRE ATLAS AML.T0024", "AML.T0057"],
    },
    "LLM05:2025": {
        "title": "Improper Output Handling",
        "summary": "Model output was trusted or rendered without validation, "
                   "enabling injection or filter bypass downstream.",
        "controls": [
            "Treat model output as untrusted: encode/escape before rendering, "
            "and validate against a strict schema before use.",
            "Never pass model output directly to a shell, SQL, or eval sink.",
            "Normalize and decode obfuscated output (base64/ROT13) before "
            "applying content policy.",
        ],
        "references": ["OWASP LLM05:2025"],
    },
    "LLM06:2025": {
        "title": "Excessive Agency",
        "summary": "The model was able to trigger actions or privileges beyond "
                   "what the task required.",
        "controls": [
            "Grant the minimum set of tools/functions needed; remove open-ended "
            "or destructive capabilities.",
            "Gate high-impact tool calls behind human-in-the-loop confirmation.",
            "Scope credentials per-tool and per-user; never share a broad key.",
            "Treat tool calls requested inside user or retrieved content as "
            "untrusted — require the invoking intent to originate from the "
            "authenticated user, not from document/RAG text (defends against "
            "confused-deputy and cross-tool request forgery).",
            "Ignore in-band claims of elevated privilege ('I am the admin') — "
            "authorize via the application layer, not the prompt.",
        ],
        "references": ["OWASP LLM06:2025"],
    },
    "LLM07:2025": {
        "title": "System Prompt Leakage",
        "summary": "The system prompt or hidden instructions were extracted.",
        "controls": [
            "Assume the system prompt is discoverable — never store secrets, "
            "credentials, or access logic in it.",
            "Move authorization and business rules into application code, not "
            "prompt text.",
            "Detect and refuse verbatim-disclosure requests with a guardrail.",
        ],
        "references": ["OWASP LLM07:2025", "MITRE ATLAS AML.T0057"],
    },
    "LLM10:2025": {
        "title": "Unbounded Consumption",
        "summary": "The model was driven to excessive token/compute use "
                   "(cost or denial-of-service).",
        "controls": [
            "Enforce per-request max_tokens, output length caps, and timeouts.",
            "Rate-limit and quota per user/API key; detect runaway or looping "
            "generations.",
            "Monitor cost per session and alert on anomalous consumption.",
        ],
        "references": ["OWASP LLM10:2025", "MITRE ATLAS AML.T0029", "AML.T0034"],
    },
}

_GENERIC = {
    "title": "General Hardening",
    "summary": "Finding is outside the mapped OWASP categories.",
    "controls": [
        "Apply defense-in-depth: input validation, output moderation, "
        "least-privilege tools, and independent guardrails.",
    ],
    "references": ["OWASP GenAI Security Project"],
}


def _owasp_for_technique_id(technique_id: str) -> str:
    """Resolve a logged technique_id (incl. multi-turn 'JB-003:CHAIN-x') to OWASP."""
    if not technique_id:
        return ""
    base = technique_id.split(":", 1)[0]  # strip chain suffix
    tech = ATTACK_TECHNIQUES.get(base)
    return tech.owasp if tech else ""


def remediation_for(owasp_id: str) -> dict:
    """Return the remediation entry for an OWASP LLM category (generic fallback)."""
    return REMEDIATIONS.get(owasp_id, _GENERIC)


def remediations_for_findings(results: list) -> list:
    """Aggregate successful findings into a prioritized remediation report.

    Groups confirmed hits by OWASP category and attaches mitigation guidance,
    ordered by number of affected findings (highest exposure first).
    """
    buckets: dict = {}
    for r in results:
        if not r.get("success"):
            continue
        owasp = _owasp_for_technique_id(r.get("technique_id", ""))
        key = owasp or "UNMAPPED"
        bucket = buckets.setdefault(key, {"techniques": set(), "count": 0})
        bucket["techniques"].add(r.get("technique_id", "?"))
        bucket["count"] += 1

    report = []
    for owasp_id, data in buckets.items():
        rem = remediation_for(owasp_id)
        report.append({
            "owasp": owasp_id,
            "owasp_name": OWASP_LLM_2025.get(owasp_id, rem["title"]),
            "finding_count": data["count"],
            "affected_techniques": sorted(data["techniques"]),
            "summary": rem["summary"],
            "controls": rem["controls"],
            "references": rem["references"],
        })

    report.sort(key=lambda x: x["finding_count"], reverse=True)
    return report
