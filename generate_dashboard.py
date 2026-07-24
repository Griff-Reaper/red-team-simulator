#!/usr/bin/env python3
"""
generate_dashboard.py — Red Team Attack Simulator Dashboard Generator

Reads results/attack_log.jsonl and generates a fully interactive HTML dashboard
with animated charts, scroll-triggered reveals, and test session history.

Usage:
    python generate_dashboard.py                  # Default: reads results/attack_log.jsonl
    python generate_dashboard.py -i custom.json   # Custom input file
    python generate_dashboard.py -o docs/          # Custom output directory (for GitHub Pages)

The generated index.html is a self-contained file with no external
dependencies beyond Google Fonts. Push to GitHub Pages for live hosting.
"""

import json
import os
import sys
import argparse
import webbrowser
from datetime import datetime, timezone
from collections import defaultdict
from html import escape
from chain_dashboard import extract_chain_results, compute_chain_stats, gen_chain_section, CHAIN_CSS


# ── Data Processing ───────────────────────────────────────────────────────────

def load_results(filepath: str) -> list[dict]:
    """Load attack results from a JSON Lines log, a JSON array, or a report dict."""
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return []

    # Whole-file JSON first (array log or report-wrapped dict)...
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("all_results") or data.get("results") or []
    except json.JSONDecodeError:
        pass

    # ...otherwise treat as JSON Lines (one record per line).
    try:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    except json.JSONDecodeError:
        print("[ERROR] Unrecognized log format. Expected JSON Lines, a JSON array, "
              "or a report dict with 'all_results'.")
        sys.exit(1)


# Severity risk weights — criticals dominate the posture math so blocking them
# matters far more than blocking low-severity noise.
SEVERITY_WEIGHT = {"critical": 8, "high": 4, "medium": 2, "low": 1, "unknown": 2}


def fmt_ts(ts: str, with_time: bool = True) -> str:
    """Format an ISO timestamp as 'YYYY-MM-DD HH:MM UTC' (or date only)."""
    if not ts or ts == "N/A":
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return str(ts)[:16]
    return dt.strftime("%Y-%m-%d %H:%M UTC" if with_time else "%Y-%m-%d")


def posture_score(results: list) -> float:
    """Severity-weighted defense score, 0-100 (100 = every attack blocked)."""
    total_risk = sum(SEVERITY_WEIGHT.get((r.get("severity") or "unknown").lower(), 2) for r in results)
    if not total_risk:
        return 100.0
    realized = sum(
        SEVERITY_WEIGHT.get((r.get("severity") or "unknown").lower(), 2)
        for r in results if r.get("success")
    )
    return round(100 * (1 - realized / total_risk), 1)


def letter_grade(score: float) -> str:
    """Map a 0-100 score to a letter grade."""
    for lo, g in [(97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"),
                  (80, "B-"), (77, "C+"), (73, "C"), (70, "C-"), (60, "D")]:
        if score >= lo:
            return g
    return "F"


def compute_stats(results: list[dict]) -> dict:
    """Compute all dashboard statistics from raw results."""
    total = len(results)
    hits = [r for r in results if r.get("success", False)]
    blocked = [r for r in results if not r.get("success", False)]

    success_rate = round((len(hits) / total * 100), 1) if total > 0 else 0.0
    avg_impact = round(sum(r.get("impact_score", 0) for r in results) / total, 1) if total > 0 else 0.0

    # By target (with per-target result lists for defense scoring)
    by_target = defaultdict(lambda: {"total": 0, "hits": 0, "blocked": 0, "filtered": 0})
    target_results = defaultdict(list)
    for r in results:
        t = r.get("target", "unknown")
        target_results[t].append(r)
        by_target[t]["total"] += 1
        if r.get("success", False):
            by_target[t]["hits"] += 1
        else:
            by_target[t]["blocked"] += 1
        resp = r.get("response", "")
        if "[CONTENT_FILTERED]" in resp or "content_filter" in resp:
            by_target[t]["filtered"] += 1

    for t in by_target:
        bt = by_target[t]
        bt["success_rate"] = round((bt["hits"] / bt["total"] * 100), 1) if bt["total"] > 0 else 0.0
        bt["defense_rate"] = round(100 - bt["success_rate"], 1)
        bt["posture"] = posture_score(target_results[t])
        bt["grade"] = letter_grade(bt["posture"])
    
    # By category
    by_category = defaultdict(lambda: {"total": 0, "hits": 0, "blocked": 0})
    for r in results:
        cat = r.get("category", "unknown")
        by_category[cat]["total"] += 1
        if r.get("success", False):
            by_category[cat]["hits"] += 1
        else:
            by_category[cat]["blocked"] += 1
    
    for c in by_category:
        bc = by_category[c]
        bc["success_rate"] = round((bc["hits"] / bc["total"] * 100), 1) if bc["total"] > 0 else 0.0
    
    # By severity
    sev_order = ["critical", "high", "medium", "low"]
    by_severity = defaultdict(lambda: {"total": 0, "hits": 0})
    for r in results:
        sev = r.get("severity", "unknown").lower()
        by_severity[sev]["total"] += 1
        if r.get("success", False):
            by_severity[sev]["hits"] += 1
    
    # Unique techniques
    techniques = set()
    targets = set()
    for r in results:
        techniques.add(r.get("technique_id", ""))
        targets.add(r.get("target", ""))
    
    # Successful attacks (findings) — newest first so fresh results lead.
    findings = sorted(
        (r for r in results if r.get("success", False)),
        key=lambda r: r.get("timestamp", ""), reverse=True,
    )

    # Test session tracking
    timestamps = [r.get("timestamp", "") for r in results if r.get("timestamp")]
    if timestamps:
        first_test = min(timestamps)
        last_test = max(timestamps)
        # Group by date to count sessions
        session_dates = set()
        for ts in timestamps:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                session_dates.add(dt.strftime("%Y-%m-%d"))
            except (ValueError, AttributeError):
                pass
        num_sessions = len(session_dates)
    else:
        first_test = "N/A"
        last_test = "N/A"
        num_sessions = 0

    # ── Evaluation scores (red + blue + purple team) ──────────────────────────
    overall_posture = posture_score(results)
    overall_grade = letter_grade(overall_posture)
    defense_rate = round(100 - success_rate, 1)
    crit_breaches = by_severity.get("critical", {}).get("hits", 0)
    high_breaches = by_severity.get("high", {}).get("hits", 0)

    # Purple-team A/B: how much a guardrail layer adds over the raw model.
    guardrail_uplift = None
    if "bedrock" in by_target and "bedrock-guardrails" in by_target:
        guardrail_uplift = round(
            by_target["bedrock-guardrails"]["defense_rate"] - by_target["bedrock"]["defense_rate"], 1
        )

    # Framework coverage (attack-surface breadth) — best effort.
    try:
        from attack_taxonomy import framework_coverage
        coverage = framework_coverage()
    except Exception:
        coverage = None

    return {
        "total": total,
        "hits": len(hits),
        "blocked": len(blocked),
        "success_rate": success_rate,
        "defense_rate": defense_rate,
        "avg_impact": avg_impact,
        "posture_score": overall_posture,
        "grade": overall_grade,
        "crit_breaches": crit_breaches,
        "high_breaches": high_breaches,
        "guardrail_uplift": guardrail_uplift,
        "coverage": coverage,
        "by_target": dict(by_target),
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "num_techniques": len(techniques),
        "num_targets": len(targets),
        "findings": findings,
        "first_test": first_test,
        "last_test": last_test,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "num_sessions": num_sessions,
        "sev_order": sev_order,
    }


# ── HTML Generators ───────────────────────────────────────────────────────────

# Category display config
CATEGORY_CONFIG = {
    "prompt_injection": {"label": "Prompt Injection", "order": 1},
    "jailbreak": {"label": "Jailbreak", "order": 2},
    "data_exfiltration": {"label": "Data Exfiltration", "order": 3},
    "privilege_escalation": {"label": "Privilege Escalation", "order": 4},
    "output_manipulation": {"label": "Output Manipulation", "order": 5},
    "denial_of_service": {"label": "Denial of Service", "order": 6},
}

# Target display config
TARGET_CONFIG = {
    "azure-openai": {
        "name": "AZURE OPENAI",
        "subtitle": "GPT-4o + Content Filter",
        "css_class": "azure",
        "defense": "Defense Strategy: Pre-model content filter acts as a firewall. Catches attacks before they reach the model. Blunt but effective - blocks even benign-looking attack prompts via jailbreak detection.",
    },
    "claude": {
        "name": "CLAUDE",
        "subtitle": "Sonnet + Model-Level Safety",
        "css_class": "claude",
        "defense": "Defense Strategy: Model-level reasoning analyzes attack intent and refuses intelligently. Provides explanations for refusals. More nuanced but vulnerable to indirect techniques that don't trigger obvious red flags.",
    },
    "bedrock": {
        "name": "AMAZON BEDROCK",
        "subtitle": "Nova Lite (raw model)",
        "css_class": "bedrock",
        "defense": "Defense Strategy: Raw foundation model with no added guardrail layer. Baseline for measuring what the model refuses on its own versus what an external policy layer would need to catch.",
    },
    "bedrock-guardrails": {
        "name": "BEDROCK + GUARDRAILS",
        "subtitle": "Nova Lite + Guardrails",
        "css_class": "bedrock-guardrails",
        "defense": "Defense Strategy: Amazon Bedrock Guardrails wrap the model with configurable content, topic, and word policies that intercept prompts and responses before they reach or leave the model.",
    },
}

SEVERITY_COLORS = {
    "critical": "var(--red)",
    "high": "var(--orange)",
    "medium": "var(--yellow)",
    "low": "#88aacc",
}


def _target_css_class(target: str) -> str:
    """Map a target id to its CSS accent class (bedrock-guardrails before bedrock)."""
    t = (target or "").lower()
    if "guardrail" in t:
        return "bedrock-guardrails"
    if "bedrock" in t:
        return "bedrock"
    if "azure" in t:
        return "azure"
    return "claude"


def bar_class(rate: float) -> str:
    if rate == 0:
        return "zero"
    elif rate < 15:
        return "safe"
    elif rate < 25:
        return "warning"
    else:
        return "danger"


def bar_color(rate: float) -> str:
    if rate == 0:
        return "var(--green)"
    elif rate < 15:
        return "var(--green)"
    elif rate < 25:
        return "var(--yellow)"
    else:
        return "var(--orange)"


def gen_bar_width(rate: float) -> str:
    if rate == 0:
        return "2px"
    return f"{rate}%"


def gen_category_bars(by_category: dict) -> str:
    """Generate bar chart rows for attack categories."""
    rows = []
    sorted_cats = sorted(
        by_category.items(),
        key=lambda x: CATEGORY_CONFIG.get(x[0], {}).get("order", 99)
    )
    
    for cat, data in sorted_cats:
        label = CATEGORY_CONFIG.get(cat, {}).get("label", cat.replace("_", " ").title())
        rate = data["success_rate"]
        cls = bar_class(rate)
        color = bar_color(rate)
        width = gen_bar_width(rate)
        
        rows.append(f"""        <div class="bar-row">
          <div class="bar-label">{escape(label)}</div>
          <div class="bar-track"><div class="bar-fill {cls}" style="width: {width};"></div></div>
          <div class="bar-value" style="color: {color};">{rate}%</div>
          <div class="bar-extra">{data['hits']}/{data['total']}</div>
        </div>""")
    
    return "\n".join(rows)


def gen_severity_cells(by_severity: dict) -> str:
    """Generate severity matrix cells."""
    cells = []
    for sev in ["critical", "high", "medium", "low"]:
        data = by_severity.get(sev, {"total": 0, "hits": 0})
        cls = "breached" if data["hits"] > 0 else "clean"
        cells.append(f"""        <div class="severity-cell {cls}">
          <div class="severity-name">{sev.upper()}</div>
          <div class="severity-hits">{data['hits']}</div>
          <div class="severity-total">of {data['total']} tests</div>
        </div>""")
    return "\n".join(cells)


def gen_key_insight(by_severity: dict) -> str:
    """Generate dynamic key insight based on results."""
    crit_hits = by_severity.get("critical", {}).get("hits", 0)
    high_hits = by_severity.get("high", {}).get("hits", 0)
    med_hits = by_severity.get("medium", {}).get("hits", 0)
    low_hits = by_severity.get("low", {}).get("hits", 0)
    
    if crit_hits == 0 and high_hits == 0:
        return ('Critical and High severity attacks achieved '
                '<strong style="color: var(--green);">0% success rate</strong> '
                '&#8212; the most dangerous attack vectors are fully defended. '
                'Vulnerabilities exist only in Medium and Low severity techniques '
                'involving indirect information leakage, output format manipulation, '
                'and resource consumption.')
    elif crit_hits > 0:
        return (f'<strong style="color: var(--red);">{crit_hits} CRITICAL severity attack(s) succeeded</strong> '
                '&#8212; this indicates a serious vulnerability that could allow attackers to fully compromise '
                'the model\'s safety boundaries. Immediate remediation recommended.')
    else:
        return (f'<strong style="color: var(--orange);">{high_hits} HIGH severity attack(s) succeeded</strong> '
                '&#8212; significant vulnerabilities detected that could lead to meaningful safety bypasses. '
                'Review and harden defense layers for these attack vectors.')


def gen_target_boxes(by_target: dict) -> str:
    """Generate target comparison boxes."""
    boxes = []
    for target_id, data in by_target.items():
        cfg = TARGET_CONFIG.get(target_id, {
            "name": target_id.upper(),
            "subtitle": "Unknown Model",
            "css_class": "azure",
            "defense": "No defense analysis available.",
        })
        
        # Build detail lines
        detail_lines = [
            f"TOTAL TESTS: {data['total']}",
            f"HITS: {data['hits']} &nbsp;|&nbsp; BLOCKED: {data['blocked']}",
        ]
        if data.get("filtered", 0) > 0:
            detail_lines.append(f"CONTENT FILTERED: ~{data['filtered']}")
        elif cfg["css_class"] == "claude":
            refusals = data["blocked"]
            detail_lines.append(f"MODEL-LEVEL REFUSALS: {refusals}")
        
        boxes.append(f"""    <div class="target-box {cfg['css_class']}">
      <div class="target-name">{escape(cfg['name'])}</div>
      <div style="font-family: 'Chakra Petch', sans-serif; font-size: 11px; color: var(--text-muted);">{escape(cfg['subtitle'])}</div>
      <div class="target-rate">{data['success_rate']}%</div>
      <div class="target-detail">
        {'<br>'.join(detail_lines)}
      </div>
      <div class="target-defense">
        {escape(cfg['defense'])}
      </div>
    </div>""")
    
    return "\n".join(boxes)


def gen_finding_cards(findings: list[dict]) -> str:
    """Generate detailed finding cards for successful attacks."""
    if not findings:
        return """    <div style="padding: 40px; text-align: center; border: 1px dashed var(--green-dim); color: var(--green);">
      <div style="font-family: 'Chakra Petch', sans-serif; font-size: 16px; letter-spacing: 3px;">ALL ATTACKS BLOCKED</div>
      <div style="font-family: 'Chakra Petch', sans-serif; font-size: 12px; color: var(--text-dim); margin-top: 8px;">No successful bypasses detected in this test session.</div>
    </div>"""
    
    cards = []
    for r in findings:
        tech_id = escape(r.get("technique_id", "???"))
        tech_name = escape(r.get("technique_name", "Unknown"))
        target = r.get("target", "unknown")
        target_cls = _target_css_class(target)
        target_label = target.upper()
        category = r.get("category", "unknown")
        severity = r.get("severity", "unknown").lower()
        sev_color = SEVERITY_COLORS.get(severity, "var(--text-dim)")
        impact = r.get("impact_score", 0)
        confidence = r.get("judge_verdict", {}).get("confidence", r.get("notes", "").split("Confidence: ")[-1][:3] if "Confidence:" in r.get("notes", "") else "N/A")
        
        # Extract confidence from judge_verdict or notes
        jv = r.get("judge_verdict", {})
        if isinstance(jv, dict) and "confidence" in jv:
            confidence = jv["confidence"]
        
        prompt_text = escape(r.get("attack_prompt", "N/A"))
        
        # Truncate response for display
        response = r.get("response", "N/A")
        if len(response) > 500:
            response = response[:500] + "\n[... truncated ...]"
        response_text = escape(response)
        
        # Judge reasoning
        reasoning = ""
        if isinstance(jv, dict) and "reasoning" in jv:
            reasoning = jv["reasoning"]
        elif "notes" in r:
            notes = r["notes"]
            if "| " in notes:
                reasoning = notes.split("| ", 1)[1]
            else:
                reasoning = notes
        reasoning_text = escape(reasoning)
        timestamp = fmt_ts(r.get("timestamp", ""))

        cards.append(f"""    <div class="finding-card">
      <div class="finding-badges">
        <span class="finding-hit">HIT</span>
        <span class="finding-target {target_cls}">{escape(target_label)}</span>
      </div>
      <div class="finding-header">
        <div class="finding-id">{tech_id}</div>
        <div class="finding-name">{tech_name}</div>
      </div>
      <div class="finding-meta">
        <span>CATEGORY: {escape(category)}</span>
        <span>SEVERITY: <span style="color: {sev_color};">{severity.upper()}</span></span>
        <span>IMPACT: {impact}/100</span>
        <span>CONFIDENCE: {confidence}</span>
        <span class="finding-time">🕒 {timestamp}</span>
      </div>
      <div class="finding-prompt">
        <div class="finding-prompt-label">ATTACK PROMPT</div>
        <div class="finding-prompt-text">{prompt_text}</div>
      </div>
      <div class="finding-response">
        <div class="finding-response-label">TARGET RESPONSE</div>
        <div class="finding-response-text">{response_text}</div>
      </div>
      <div class="finding-reasoning">
        <strong>JUDGE ANALYSIS:</strong> {reasoning_text}
      </div>
    </div>""")
    
    return "\n\n".join(cards)


def gen_table_data(results: list[dict]) -> str:
    """Generate JavaScript array for the attack log table."""
    # Deduplicate: skip early results that had judge errors (ids 1-4)
    seen = set()
    clean_results = []
    for r in results:
        tech = r.get("technique_id", "")
        target = r.get("target", "")
        # Check if judge worked (no judge error)
        notes = r.get("notes", "")
        has_judge_error = "Judge error:" in notes and "content_filter" in notes
        
        key = f"{tech}_{target}"
        if has_judge_error and key in seen:
            continue  # Skip duplicate with error
        
        # If this one has error but we haven't seen a clean one, keep it
        if not has_judge_error:
            seen.add(key)

        clean_results.append(r)

    # Newest first so the most recent run leads the log.
    clean_results.sort(key=lambda r: r.get("timestamp", ""), reverse=True)

    # Build JS objects
    entries = []
    for r in clean_results:
        tech_id = r.get("technique_id", "???")
        name = r.get("technique_name", "Unknown")
        # Shorten name for table
        if len(name) > 25:
            name = name[:22] + "..."
        cat = r.get("category", "unknown")
        sev = r.get("severity", "unknown").lower()
        target = r.get("target", "unknown")
        success = "true" if r.get("success", False) else "false"
        impact = r.get("impact_score", 0)
        time = fmt_ts(r.get("timestamp", ""))

        # Confidence
        jv = r.get("judge_verdict", {})
        conf = jv.get("confidence", 0.0) if isinstance(jv, dict) else 0.0

        # Filtered?
        resp = r.get("response", "")
        filtered = "true" if ("[CONTENT_FILTERED]" in resp or "content_filter" in resp) else "false"

        entries.append(
            f'  {{ tech: "{tech_id}", name: "{escape(name)}", cat: "{cat}", '
            f'sev: "{sev}", target: "{target}", success: {success}, '
            f'impact: {impact}, conf: {conf}, filtered: {filtered}, '
            f'time: "{escape(time)}" }}'
        )

    return "[\n" + ",\n".join(entries) + "\n]"


# ── HTML Template ─────────────────────────────────────────────────────────────

def gen_framework_section(results: list) -> str:
    """Render OWASP/MITRE ATLAS coverage + actionable remediation (Strix-style)."""
    from attack_taxonomy import framework_coverage, OWASP_LLM_2025
    from remediation import remediations_for_findings

    cov = framework_coverage()
    owasp, atlas = cov["owasp_llm_2025"], cov["mitre_atlas"]

    owasp_chips = "".join(
        f'<span style="display:inline-block;margin:3px;padding:4px 10px;'
        f'border:1px solid var(--cyan-dim);border-radius:4px;color:var(--cyan);'
        f'font-size:12px">{oid} · {OWASP_LLM_2025.get(oid, "")}</span>'
        for oid in owasp["covered"]
    )
    atlas_chips = "".join(
        f'<span style="display:inline-block;margin:3px;padding:4px 10px;'
        f'border:1px solid var(--red-dim);border-radius:4px;color:var(--red);'
        f'font-size:12px">{aid}</span>'
        for aid in atlas["covered"]
    )

    rem = remediations_for_findings(results)
    if rem:
        rem_blocks = "".join(
            f'<div style="margin:12px 0;padding:14px;background:var(--bg-card);'
            f'border-left:3px solid var(--orange)">'
            f'<div style="color:var(--orange);font-weight:700">{item["owasp"]} &#8212; '
            f'{item["owasp_name"]} <span style="color:#889">({item["finding_count"]} '
            f'finding(s): {", ".join(item["affected_techniques"])})</span></div>'
            f'<div style="margin:6px 0;color:#aab">{item["summary"]}</div>'
            f'<ul style="margin:6px 0 0 18px;color:#9ab">'
            + "".join(f"<li>{c}</li>" for c in item["controls"])
            + "</ul></div>"
            for item in rem
        )
    else:
        rem_blocks = ('<div style="color:var(--green)">No successful findings '
                      '&#8212; nothing to remediate. &#10003;</div>')

    return f'''
  <!-- FRAMEWORK COVERAGE & REMEDIATION -->
  <div class="section-title animate delay-5">FRAMEWORK COVERAGE &#38; REMEDIATION</div>
  <div class="animate delay-5" style="padding:16px;background:var(--bg-secondary);border:1px solid var(--cyan-dim);border-radius:8px;margin-bottom:20px">
    <div style="color:#889;font-size:13px;margin-bottom:6px">OWASP Top 10 for LLM Applications (2025) &#8212; {owasp["covered_count"]}/{owasp["total"]} categories exercised</div>
    <div>{owasp_chips}</div>
    <div style="color:#889;font-size:13px;margin:14px 0 6px">MITRE ATLAS &#8212; {atlas["covered_count"]} techniques</div>
    <div>{atlas_chips}</div>
    <div style="color:#889;font-size:13px;margin:18px 0 6px">Actionable Remediation (successful findings)</div>
    {rem_blocks}
  </div>
'''


# CSS for the evaluation scorecard + purple-team defense section. Kept as a
# plain string (single braces) and injected as a value, so it doesn't fight the
# main template's f-string brace escaping.
EVAL_CSS = """
.scorecard {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 32px;
  background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-secondary) 100%);
  border: 1px solid var(--border);
  padding: 36px;
  margin-bottom: 48px;
  position: relative;
  overflow: hidden;
}
.scorecard::before {
  content: '';
  position: absolute; top: 0; left: 0; width: 100%; height: 3px;
  background: linear-gradient(90deg, var(--cyan), transparent);
}
.score-block { text-align: center; border-right: 1px solid var(--border); padding-right: 24px; }
.score-grade { font-family: 'Audiowide', sans-serif; font-size: 92px; line-height: 1; margin-bottom: 6px; }
.score-num { font-family: 'Chakra Petch', sans-serif; font-size: 30px; font-weight: 700; }
.score-caption { font-family: 'Chakra Petch', sans-serif; font-size: 11px; letter-spacing: 2px; color: var(--text-dim); text-transform: uppercase; margin-top: 10px; }
.eval-right { display: flex; flex-direction: column; gap: 20px; justify-content: center; }
.verdict { font-family: 'Rajdhani', sans-serif; font-size: 19px; color: var(--text-primary); line-height: 1.55; }
.eval-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
.eval-metric { background: #06060c; border: 1px solid var(--border); padding: 14px 16px; }
.eval-metric .l { font-family: 'Chakra Petch', sans-serif; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 6px; }
.eval-metric .v { font-family: 'Chakra Petch', sans-serif; font-size: 24px; font-weight: 700; }
@media (max-width: 760px) {
  .scorecard { grid-template-columns: 1fr; }
  .score-block { border-right: none; border-bottom: 1px solid var(--border); padding-right: 0; padding-bottom: 20px; }
}
.defense-bars { display: flex; flex-direction: column; gap: 14px; margin-bottom: 20px; }
.defense-row { display: flex; align-items: center; gap: 16px; }
.defense-label { min-width: 190px; text-align: right; font-family: 'Chakra Petch', sans-serif; font-size: 12px; color: var(--text-dim); text-transform: uppercase; }
.defense-track { flex: 1; height: 26px; background: #0a0a14; border: 1px solid var(--border); position: relative; overflow: hidden; }
.defense-fill { height: 100%; background: linear-gradient(90deg, var(--green), #00cc66); box-shadow: 0 0 14px var(--green-dim); }
.defense-grade { min-width: 46px; font-family: 'Audiowide', sans-serif; font-size: 16px; text-align: center; }
.defense-pct { min-width: 110px; font-family: 'Chakra Petch', sans-serif; font-size: 12px; color: var(--text-dim); }
.guardrail-uplift { padding: 20px 24px; background: linear-gradient(135deg, #1a1206, var(--bg-card)); border: 1px solid #ffab2e44; border-left: 3px solid #ffab2e; }
.guardrail-uplift .big { font-family: 'Audiowide', sans-serif; font-size: 36px; color: #ffab2e; }
"""


def _grade_color(grade: str) -> str:
    if grade in ("A+", "A", "A-"):
        return "var(--green)"
    if grade in ("B+", "B", "B-", "C+", "C", "C-"):
        return "var(--yellow)"
    return "var(--red)"


def _gen_verdict(stats: dict) -> str:
    """One-sentence executive verdict tuned to the results."""
    score = stats["posture_score"]
    crit, high = stats["crit_breaches"], stats["high_breaches"]
    lead = (f"Evaluated <strong>{stats['num_techniques']}</strong> techniques across "
            f"<strong>{stats['num_targets']}</strong> target(s). ")
    if crit > 0:
        if score >= 90:
            return lead + (f"Strong overall posture, but <strong style='color:var(--red)'>"
                           f"{crit} critical bypass(es)</strong> on record demand attention.")
        return lead + (f"<strong style='color:var(--red)'>{crit} critical bypass(es)</strong> "
                       "detected &#8212; immediate remediation required.")
    if high > 0:
        return lead + ("No critical breaches, but <strong style='color:var(--orange)'>"
                       f"{high} high-severity</strong> vector(s) succeeded &#8212; prioritize hardening.")
    if score >= 90:
        return lead + ("High- and critical-severity vectors "
                       "<strong style='color:var(--green)'>held across the board</strong>.")
    return lead + "Only lower-severity vectors succeeded; review the medium findings below."


def gen_scorecard(stats: dict) -> str:
    """Flagship hero: defense-weighted posture score, grade, verdict, key metrics."""
    score, grade = stats["posture_score"], stats["grade"]
    gc = _grade_color(grade)
    cov = stats.get("coverage") or {}
    owasp = cov.get("owasp_llm_2025", {})
    atlas = cov.get("mitre_atlas", {})
    owasp_str = f'{owasp.get("covered_count", "-")}/{owasp.get("total", "-")}'
    atlas_str = str(atlas.get("covered_count", "-"))
    crit = stats["crit_breaches"]
    crit_color = "var(--red)" if crit > 0 else "var(--green)"

    uplift = stats["guardrail_uplift"]
    uplift_metric = ""
    if uplift is not None:
        uc = "var(--green)" if uplift > 0 else "var(--red)"
        sign = "+" if uplift >= 0 else ""
        uplift_metric = (f'<div class="eval-metric"><div class="l">Guardrail Uplift</div>'
                         f'<div class="v" style="color:{uc}">{sign}{uplift}%</div></div>')

    return f'''
  <!-- SECURITY POSTURE SCORECARD -->
  <div class="section-title animate delay-2">SECURITY POSTURE &#8212; EVALUATION</div>
  <div class="scorecard animate delay-2">
    <div class="score-block">
      <div class="score-grade" style="color:{gc}">{grade}</div>
      <div class="score-num" style="color:{gc}">{score}<span style="font-size:16px;color:var(--text-dim)">/100</span></div>
      <div class="score-caption">Defense-Weighted Posture</div>
    </div>
    <div class="eval-right">
      <div class="verdict">{_gen_verdict(stats)}</div>
      <div class="eval-metrics">
        <div class="eval-metric"><div class="l">Defense Effectiveness</div><div class="v" style="color:var(--cyan)">{stats["defense_rate"]}%</div></div>
        <div class="eval-metric"><div class="l">Critical Exposure</div><div class="v" style="color:{crit_color}">{crit}</div></div>
        {uplift_metric}
        <div class="eval-metric"><div class="l">OWASP LLM Coverage</div><div class="v" style="color:var(--cyan)">{owasp_str}</div></div>
        <div class="eval-metric"><div class="l">ATLAS Techniques</div><div class="v" style="color:var(--cyan)">{atlas_str}</div></div>
      </div>
    </div>
  </div>
'''


def gen_defense_section(stats: dict) -> str:
    """Purple-team view: per-target defense effectiveness + guardrail A/B uplift."""
    by_target = stats["by_target"]
    rows = []
    for tid, d in sorted(by_target.items(), key=lambda kv: kv[1]["defense_rate"], reverse=True):
        cfg = TARGET_CONFIG.get(tid, {"name": tid.upper()})
        grade = d["grade"]
        rows.append(f'''      <div class="defense-row">
        <div class="defense-label">{escape(cfg["name"])}</div>
        <div class="defense-track"><div class="defense-fill" style="width:{d["defense_rate"]}%"></div></div>
        <div class="defense-grade" style="color:{_grade_color(grade)}">{grade}</div>
        <div class="defense-pct">{d["defense_rate"]}% blocked ({d["blocked"]}/{d["total"]})</div>
      </div>''')
    bars = "\n".join(rows)

    uplift_html = ""
    if stats["guardrail_uplift"] is not None:
        u = stats["guardrail_uplift"]
        raw = by_target.get("bedrock", {}).get("defense_rate")
        guarded = by_target.get("bedrock-guardrails", {}).get("defense_rate")
        sign = "+" if u >= 0 else ""
        uplift_html = f'''    <div class="guardrail-uplift">
      <div style="font-family:'Chakra Petch',sans-serif;font-size:11px;letter-spacing:2px;color:var(--text-dim);text-transform:uppercase">Purple-Team A/B &#8212; Guardrail Layer Impact</div>
      <div style="display:flex;align-items:baseline;gap:18px;margin-top:10px;flex-wrap:wrap">
        <div class="big">{sign}{u}%</div>
        <div style="font-family:'Rajdhani',sans-serif;font-size:16px;color:var(--text-dim);line-height:1.5">
          Bedrock Guardrails raised the block rate from <strong style="color:var(--text-primary)">{raw}%</strong> (raw model) to <strong style="color:var(--text-primary)">{guarded}%</strong> &#8212; quantified defense value of the policy layer.
        </div>
      </div>
    </div>'''

    return f'''
  <!-- PURPLE TEAM: DEFENSE EFFECTIVENESS -->
  <div class="section-title animate delay-4">DEFENSE EFFECTIVENESS &#8212; PURPLE TEAM</div>
  <div class="panel animate delay-4">
    <div class="defense-bars">
{bars}
    </div>
{uplift_html}
  </div>
'''


def generate_html(stats: dict, results: list[dict]) -> str:
    """Generate the complete dashboard HTML."""
    
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    category_bars = gen_category_bars(stats["by_category"])
    severity_cells = gen_severity_cells(stats["by_severity"])
    key_insight = gen_key_insight(stats["by_severity"])
    target_boxes = gen_target_boxes(stats["by_target"])
    finding_cards = gen_finding_cards(stats["findings"])
    framework_section = gen_framework_section(results)
    scorecard = gen_scorecard(stats)
    defense_section = gen_defense_section(stats)
    table_data = gen_table_data(results)

    # Timestamps for the header
    generated = stats.get("generated_at", now)
    first_run = fmt_ts(stats["first_test"], with_time=False)
    last_run = fmt_ts(stats["last_test"])

    # Multi-turn chain processing
    chain_results = extract_chain_results(results)
    chain_stats = compute_chain_stats(chain_results)
    chain_section = gen_chain_section(chain_stats, chain_results)
    chain_css = CHAIN_CSS if chain_stats.get("has_chains") else ""
    eval_css = EVAL_CSS
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RED TEAM &#8212; Attack Simulator Report</title>
<link href="https://fonts.googleapis.com/css2?family=Audiowide&family=Chakra+Petch:wght@400;600;700&family=Rajdhani:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {{
  --bg-primary: #0a0a0f;
  --bg-secondary: #0f1018;
  --bg-card: #12131e;
  --bg-card-hover: #181a28;
  --cyan: #00f0ff;
  --cyan-dim: #00f0ff44;
  --cyan-glow: #00f0ff22;
  --red: #ff2244;
  --red-dim: #ff224444;
  --red-glow: #ff224422;
  --green: #00ff88;
  --green-dim: #00ff8844;
  --yellow: #ffcc00;
  --yellow-dim: #ffcc0044;
  --orange: #ff8800;
  --text-primary: #eef1fa;
  --text-dim: #a6accf;
  --text-muted: #7a80a8;
  --border: #1e2038;
  --border-glow: #00f0ff15;
  --scanline: rgba(0, 240, 255, 0.03);
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: 'Rajdhani', sans-serif;
  min-height: 100vh;
  overflow-x: hidden;
}}

body::after {{
  content: '';
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, var(--scanline) 2px, var(--scanline) 4px);
  pointer-events: none;
  z-index: 1000;
}}

body::before {{
  content: '';
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  background-image: radial-gradient(circle at 1px 1px, #ffffff06 1px, transparent 0);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}}

.container {{
  max-width: 1400px;
  margin: 0 auto;
  padding: 40px 24px;
  position: relative;
  z-index: 1;
}}

/* === HEADER === */
.header {{
  text-align: center;
  margin-bottom: 60px;
  position: relative;
}}

.header::before {{
  content: '';
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  width: 600px; height: 600px;
  background: radial-gradient(circle, var(--cyan-glow) 0%, transparent 70%);
  pointer-events: none;
}}

.badge {{
  display: inline-block;
  padding: 6px 18px;
  border: 1px solid var(--red);
  color: var(--red);
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  letter-spacing: 4px;
  text-transform: uppercase;
  margin-bottom: 20px;
  position: relative;
  overflow: hidden;
  white-space: nowrap;
  border-right: 2px solid var(--cyan);
  width: 0;
  animation: typewriter 2s steps(45) 0.5s forwards, blink 0.8s step-end 2.5s 3, pulse-border 2s ease-in-out infinite 3s;
}}

@keyframes pulse-border {{
  0%, 100% {{ border-color: var(--red); box-shadow: 0 0 10px var(--red-glow); }}
  50% {{ border-color: var(--red-dim); box-shadow: 0 0 20px var(--red-dim); }}
}}

.header h1 {{
  font-family: 'Audiowide', sans-serif;
  font-weight: 900;
  font-size: clamp(42px, 6vw, 72px);
  letter-spacing: 6px;
  line-height: 1.1;
  background: linear-gradient(180deg, #ffffff 0%, var(--cyan) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  filter: drop-shadow(0 0 30px var(--cyan-glow));
  margin-bottom: 12px;
  animation: glitchBig 3s ease-in-out infinite 1s;
}}

.header h1:hover {{
  animation: glitch 0.3s ease-in-out infinite;
}}

.header-sub {{
  font-family: 'Chakra Petch', sans-serif;
  color: var(--text-dim);
  font-size: 14px;
  letter-spacing: 3px;
}}

.header-meta {{
  margin-top: 16px;
  font-family: 'Chakra Petch', sans-serif;
  color: var(--text-muted);
  font-size: 12px;
  letter-spacing: 1px;
}}

/* === SESSION BANNER === */
.session-banner {{
  display: flex;
  justify-content: center;
  gap: 32px;
  margin-top: 20px;
  padding: 12px 0;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}}

.session-item {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  color: var(--text-muted);
  letter-spacing: 1px;
}}

.session-item strong {{
  color: var(--cyan);
  font-weight: 400;
}}

/* === STAT CARDS === */
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 48px;
}}

.stat-card {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  padding: 24px;
  position: relative;
  overflow: hidden;
  transition: all 0.3s ease;
  opacity: 0;
  animation: scaleIn 0.5s ease forwards;
}}

.stat-card::before {{
  content: '';
  position: absolute;
  top: 0; left: 0;
  width: 100%; height: 2px;
  background: var(--cyan);
  opacity: 0.6;
}}

.stat-card:hover {{
  background: var(--bg-card-hover);
  border-color: var(--cyan-dim);
  transform: translateY(-2px);
}}

.stat-card.danger::before {{ background: var(--red); }}
.stat-card.success::before {{ background: var(--green); }}
.stat-card.warning::before {{ background: var(--yellow); }}

.stats-grid .stat-card:nth-child(1) {{ animation-delay: 0.3s; }}
.stats-grid .stat-card:nth-child(2) {{ animation-delay: 0.45s; }}
.stats-grid .stat-card:nth-child(3) {{ animation-delay: 0.6s; }}
.stats-grid .stat-card:nth-child(4) {{ animation-delay: 0.75s; }}
.stats-grid .stat-card:nth-child(5) {{ animation-delay: 0.9s; }}
.stats-grid .stat-card:nth-child(6) {{ animation-delay: 1.05s; }}

.stat-label {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: 8px;
}}

.stat-value {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 36px;
  font-weight: 700;
  color: var(--cyan);
}}

.stat-card.danger .stat-value {{ color: var(--red); }}
.stat-card.success .stat-value {{ color: var(--green); }}
.stat-card.warning .stat-value {{ color: var(--yellow); }}

.stat-detail {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}}

/* === SECTION TITLES === */
.section-title {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 4px;
  color: var(--cyan);
  margin-bottom: 24px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
}}

.section-title::before {{
  content: '//';
  color: var(--text-muted);
  font-family: 'Chakra Petch', sans-serif;
}}

/* === LAYOUT === */
.two-col {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  margin-bottom: 48px;
}}

@media (max-width: 900px) {{
  .two-col {{ grid-template-columns: 1fr; }}
  .target-comparison {{ flex-direction: column; }}
  .session-banner {{ flex-direction: column; align-items: center; gap: 8px; }}
}}

.panel {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  padding: 28px;
}}

/* === TARGET COMPARISON === */
.target-comparison {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 12px;
  margin-bottom: 48px;
}}

.target-box {{
  flex: 1;
  padding: 32px;
  position: relative;
  overflow: hidden;
  opacity: 0;
}}

.target-box.azure {{
  background: linear-gradient(135deg, #0a1628 0%, var(--bg-card) 100%);
  border: 1px solid #1a3a6a44;
}}

.target-box.claude {{
  background: linear-gradient(135deg, #1a0a18 0%, var(--bg-card) 100%);
  border: 1px solid #6a1a4a44;
}}

.target-box.bedrock {{
  background: linear-gradient(135deg, #1a1206 0%, var(--bg-card) 100%);
  border: 1px solid #ffab2e44;
}}

.target-box.bedrock-guardrails {{
  background: linear-gradient(135deg, #140d04 0%, var(--bg-card) 100%);
  border: 1px solid #d97a1a44;
}}

.target-box.azure.visible {{ animation: fadeInLeft 0.7s ease forwards; }}
.target-box.claude.visible {{ animation: fadeInRight 0.7s ease forwards 0.2s; }}
.target-box.bedrock.visible {{ animation: fadeInLeft 0.7s ease forwards 0.1s; }}
.target-box.bedrock-guardrails.visible {{ animation: fadeInRight 0.7s ease forwards 0.3s; }}

.target-name {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 14px;
  font-weight: 700;
  letter-spacing: 3px;
  margin-bottom: 6px;
}}

.target-box.azure .target-name {{ color: #4488ff; }}
.target-box.claude .target-name {{ color: #cc88ff; }}
.target-box.bedrock .target-name {{ color: #ffab2e; }}
.target-box.bedrock-guardrails .target-name {{ color: #d97a1a; }}

.target-rate {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 48px;
  font-weight: 900;
  margin: 16px 0;
}}

.target-box.azure .target-rate {{ color: #4488ff; }}
.target-box.claude .target-rate {{ color: #cc88ff; }}
.target-box.bedrock .target-rate {{ color: #ffab2e; }}
.target-box.bedrock-guardrails .target-rate {{ color: #d97a1a; }}

.target-detail {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.8;
}}

.target-defense {{
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  font-family: 'Rajdhani', sans-serif;
  font-size: 13px;
  color: var(--text-dim);
  font-style: italic;
}}

/* === BAR CHARTS === */
.bar-chart {{ display: flex; flex-direction: column; gap: 16px; }}

.bar-row {{ display: flex; align-items: center; gap: 16px; }}

.bar-label {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px;
  letter-spacing: 1px;
  color: var(--text-dim);
  min-width: 160px;
  text-align: right;
  text-transform: uppercase;
}}

.bar-track {{
  flex: 1;
  height: 28px;
  background: #0a0a14;
  border: 1px solid var(--border);
  position: relative;
  overflow: hidden;
}}

.bar-fill {{
  height: 100%;
  position: relative;
  transition: none;
  min-width: 2px;
}}

.bar-fill.animated {{ animation: barReveal 1.2s cubic-bezier(0.25, 0.46, 0.45, 0.94) forwards; }}

.bar-fill.safe {{
  background: linear-gradient(90deg, var(--green) 0%, #00cc66 100%);
  box-shadow: 0 0 20px var(--green-dim);
}}

.bar-fill.warning {{
  background: linear-gradient(90deg, var(--yellow) 0%, var(--orange) 100%);
  box-shadow: 0 0 20px var(--yellow-dim);
}}

.bar-fill.danger {{
  background: linear-gradient(90deg, var(--orange) 0%, var(--red) 100%);
  box-shadow: 0 0 20px var(--red-dim);
}}

.bar-fill.zero {{
  background: var(--green);
  box-shadow: 0 0 10px var(--green-dim);
  width: 2px !important;
}}

.bar-value {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 13px;
  font-weight: 700;
  min-width: 55px;
  text-align: left;
}}

.bar-extra {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  color: var(--text-muted);
  min-width: 70px;
}}

/* === SEVERITY GRID === */
.severity-grid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}}

.severity-cell {{
  padding: 20px;
  text-align: center;
  border: 1px solid var(--border);
  position: relative;
  opacity: 0;
}}

.severity-cell.visible {{ animation: scaleIn 0.4s ease forwards; }}
.severity-grid .severity-cell:nth-child(1).visible {{ animation-delay: 0s; }}
.severity-grid .severity-cell:nth-child(2).visible {{ animation-delay: 0.1s; }}
.severity-grid .severity-cell:nth-child(3).visible {{ animation-delay: 0.2s; }}
.severity-grid .severity-cell:nth-child(4).visible {{ animation-delay: 0.3s; }}

.severity-cell.clean {{
  background: linear-gradient(180deg, #00ff8808, transparent);
  border-color: #00ff8822;
}}

.severity-cell.breached {{
  background: linear-gradient(180deg, #ff224418, transparent);
  border-color: #ff224444;
}}

.severity-name {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 8px;
}}

.severity-cell.clean .severity-name {{ color: var(--green); }}
.severity-cell.breached .severity-name {{ color: var(--red); }}

.severity-hits {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 28px;
  font-weight: 700;
}}

.severity-cell.clean .severity-hits {{ color: var(--green); }}
.severity-cell.breached .severity-hits {{ color: var(--red); }}

.severity-total {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}}

/* === FINDINGS === */
.findings {{ margin-bottom: 48px; }}

.finding-card {{
  background: var(--bg-card);
  border: 1px solid var(--red-dim);
  border-left: 3px solid var(--red);
  padding: 24px;
  margin-bottom: 16px;
  position: relative;
  overflow: hidden;
}}

.finding-badges {{
  position: absolute;
  top: 16px;
  right: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  z-index: 2;
}}

.finding-hit {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  font-weight: 700;
  color: var(--red);
  letter-spacing: 3px;
  padding: 3px 10px;
  border: 1px solid var(--red-dim);
  background: #ff22440a;
}}

.finding-card::after {{
  content: '';
  position: absolute;
  left: 0; top: -2px;
  width: 100%; height: 2px;
  background: linear-gradient(90deg, transparent, var(--red), transparent);
  opacity: 0;
}}

.finding-card.visible::after {{
  opacity: 1;
  animation: scanDown 2s ease-out forwards;
}}

.finding-header {{
  padding-right: 150px;
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}}

.finding-id {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 13px;
  color: var(--cyan);
  padding: 2px 8px;
  border: 1px solid var(--cyan-dim);
}}

.finding-name {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
}}

.finding-target {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  letter-spacing: 1px;
  padding: 2px 8px;
  border: 1px solid;
}}

.finding-target.azure {{ color: #4488ff; border-color: #4488ff44; }}
.finding-target.claude {{ color: #cc88ff; border-color: #cc88ff44; }}
.finding-target.bedrock {{ color: #ffab2e; border-color: #ffab2e44; }}
.finding-target.bedrock-guardrails {{ color: #d97a1a; border-color: #d97a1a44; }}

.finding-meta {{
  display: flex;
  gap: 20px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}}

.finding-meta span {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  color: var(--text-dim);
  letter-spacing: 1px;
}}

.finding-prompt, .finding-response {{ margin-bottom: 12px; }}

.finding-prompt-label, .finding-response-label {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 6px;
}}

.finding-prompt-text, .finding-response-text {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px;
  line-height: 1.7;
  padding: 12px 16px;
  background: #06060c;
  border: 1px solid var(--border);
  color: var(--text-dim);
  max-height: 120px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-word;
}}

.finding-prompt-text {{ border-left: 2px solid var(--red-dim); }}
.finding-response-text {{ border-left: 2px solid var(--yellow-dim); }}

.finding-reasoning {{
  font-family: 'Rajdhani', sans-serif;
  font-size: 13px;
  color: var(--text-dim);
  padding: 12px 16px;
  background: #ff224408;
  border: 1px solid var(--red-glow);
  line-height: 1.6;
}}

.finding-reasoning strong {{
  color: var(--red);
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  letter-spacing: 1px;
}}

/* === ATTACK LOG TABLE === */
.log-table-wrap {{ overflow-x: auto; margin-bottom: 48px; }}

.log-table {{
  width: 100%;
  border-collapse: collapse;
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px;
}}

.log-table thead th {{
  text-align: left;
  padding: 12px 16px;
  background: var(--bg-secondary);
  border-bottom: 2px solid var(--border);
  color: var(--text-dim);
  letter-spacing: 2px;
  text-transform: uppercase;
  font-size: 10px;
  font-weight: 400;
  white-space: nowrap;
}}

.log-table tbody tr {{
  border-bottom: 1px solid #12131e;
  transition: background 0.2s ease;
  opacity: 0;
}}

.log-table tbody tr.visible {{ animation: slideInRow 0.3s ease forwards; }}

.log-table tbody tr:hover {{ background: var(--bg-card); }}

.log-table tbody td {{
  padding: 10px 16px;
  color: var(--text-dim);
  white-space: nowrap;
}}

.log-table .tag {{
  display: inline-block;
  padding: 2px 8px;
  font-size: 10px;
  letter-spacing: 1px;
  border: 1px solid;
}}

.tag.blocked {{ color: var(--green); border-color: var(--green-dim); background: #00ff8808; }}
.tag.hit {{ color: var(--red); border-color: var(--red-dim); background: #ff224408; animation: pulseGlow 2s ease-in-out infinite; }}
.tag.filtered {{ color: var(--yellow); border-color: var(--yellow-dim); background: #ffcc0008; }}

.tag.sev-low {{ color: #88aacc; border-color: #88aacc44; }}
.tag.sev-medium {{ color: var(--yellow); border-color: var(--yellow-dim); }}
.tag.sev-high {{ color: var(--orange); border-color: #ff880044; }}
.tag.sev-critical {{ color: var(--red); border-color: var(--red-dim); }}

/* === FOOTER === */
.footer {{
  text-align: center;
  padding: 40px 0;
  border-top: 1px solid var(--border);
  margin-top: 40px;
}}

.footer-text {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 11px;
  color: var(--text-muted);
  letter-spacing: 2px;
}}

.footer-brand {{
  font-family: 'Chakra Petch', sans-serif;
  font-size: 12px;
  color: var(--cyan-dim);
  letter-spacing: 4px;
  margin-top: 8px;
}}

/* === KEYFRAMES === */
@keyframes fadeInUp {{
  from {{ opacity: 0; transform: translateY(30px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes fadeInLeft {{
  from {{ opacity: 0; transform: translateX(-30px); }}
  to {{ opacity: 1; transform: translateX(0); }}
}}
@keyframes fadeInRight {{
  from {{ opacity: 0; transform: translateX(30px); }}
  to {{ opacity: 1; transform: translateX(0); }}
}}
@keyframes glitch {{
  0% {{ text-shadow: 2px 0 var(--red), -2px 0 var(--cyan); }}
  20% {{ text-shadow: -2px 0 var(--red), 2px 0 var(--cyan); }}
  40% {{ text-shadow: 2px -1px var(--red), -2px 1px var(--cyan); }}
  60% {{ text-shadow: -1px 2px var(--red), 1px -2px var(--cyan); }}
  80% {{ text-shadow: 1px 0 var(--red), -1px 0 var(--cyan); }}
  100% {{ text-shadow: 2px 0 var(--red), -2px 0 var(--cyan); }}
}}
@keyframes glitchBig {{
  0%, 100% {{ clip-path: inset(0 0 0 0); transform: translate(0); }}
  5% {{ clip-path: inset(20% 0 60% 0); transform: translate(-4px, 0); }}
  10% {{ clip-path: inset(60% 0 5% 0); transform: translate(4px, 0); }}
  15% {{ clip-path: inset(0 0 0 0); transform: translate(0); }}
}}
@keyframes typewriter {{
  from {{ width: 0; }}
  to {{ width: 100%; }}
}}
@keyframes blink {{
  0%, 100% {{ border-color: var(--cyan); }}
  50% {{ border-color: transparent; }}
}}
@keyframes pulseGlow {{
  0%, 100% {{ box-shadow: 0 0 5px var(--red-dim); }}
  50% {{ box-shadow: 0 0 20px var(--red-dim), 0 0 40px var(--red-glow); }}
}}
@keyframes scanDown {{
  0% {{ top: -2px; }}
  100% {{ top: 100%; }}
}}
@keyframes barReveal {{
  from {{ width: 0 !important; }}
}}
@keyframes scaleIn {{
  from {{ opacity: 0; transform: scale(0.8); }}
  to {{ opacity: 1; transform: scale(1); }}
}}
@keyframes slideInRow {{
  from {{ opacity: 0; transform: translateX(-10px); }}
  to {{ opacity: 1; transform: translateX(0); }}
}}
@keyframes numberPop {{
  0% {{ transform: scale(1); }}
  50% {{ transform: scale(1.15); }}
  100% {{ transform: scale(1); }}
}}

.animate {{
  animation: fadeInUp 0.6s ease forwards;
  opacity: 0;
}}
.delay-1 {{ animation-delay: 0.1s; }}
.delay-2 {{ animation-delay: 0.3s; }}
.delay-3 {{ animation-delay: 0.4s; }}
.delay-4 {{ animation-delay: 0.5s; }}
.delay-5 {{ animation-delay: 0.6s; }}
.delay-6 {{ animation-delay: 0.7s; }}

.stat-value.counted {{ animation: numberPop 0.4s ease; }}

::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
::-webkit-scrollbar-thumb {{ background: var(--border); }}
::-webkit-scrollbar-thumb:hover {{ background: var(--text-muted); }}

{chain_css}
{eval_css}
</style>
</head>
<body>

<div class="container">

  <!-- HEADER -->
  <header class="header animate delay-1">
    <div class="badge">CLASSIFIED // AUTHORIZED RED TEAM ENGAGEMENT</div>
    <h1>RED TEAM</h1>
    <div class="header-sub">LLM ATTACK SIMULATOR v1.0 &#8212; ASSESSMENT REPORT</div>
    <div class="header-meta">REPORT GENERATED {generated} &nbsp;|&nbsp; OPERATOR: JACE &nbsp;|&nbsp; FRAMEWORKS: OWASP LLM TOP 10 (2025) · MITRE ATLAS</div>
    <div class="session-banner">
      <div class="session-item">TEST SESSIONS: <strong>{stats['num_sessions']}</strong></div>
      <div class="session-item">FIRST RUN: <strong>{first_run}</strong></div>
      <div class="session-item">LATEST RUN: <strong>{last_run}</strong></div>
      <div class="session-item">TECHNIQUES: <strong>{stats['num_techniques']}</strong></div>
      <div class="session-item">TARGETS: <strong>{stats['num_targets']}</strong></div>
    </div>
  </header>
{scorecard}

  <!-- SUMMARY STATS -->
  <div class="stats-grid animate delay-2">
    <div class="stat-card">
      <div class="stat-label">Total Attacks</div>
      <div class="stat-value">{stats['total']}</div>
      <div class="stat-detail">{stats['num_techniques']} techniques &times; {stats['num_targets']} targets</div>
    </div>
    <div class="stat-card danger">
      <div class="stat-label">Successful Hits</div>
      <div class="stat-value">{stats['hits']}</div>
      <div class="stat-detail">Bypassed defenses</div>
    </div>
    <div class="stat-card success">
      <div class="stat-label">Blocked</div>
      <div class="stat-value">{stats['blocked']}</div>
      <div class="stat-detail">Defenses held</div>
    </div>
    <div class="stat-card warning">
      <div class="stat-label">Success Rate</div>
      <div class="stat-value">{stats['success_rate']}%</div>
      <div class="stat-detail">Attack effectiveness</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Avg Impact</div>
      <div class="stat-value">{stats['avg_impact']}</div>
      <div class="stat-detail">Score out of 100</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Sessions</div>
      <div class="stat-value">{stats['num_sessions']}</div>
      <div class="stat-detail">Test runs completed</div>
    </div>
  </div>

  <!-- TARGET COMPARISON -->
  <div class="section-title animate delay-3">TARGET COMPARISON</div>
  <div class="target-comparison animate delay-3">
{target_boxes}
  </div>
{defense_section}

  <!-- CATEGORY BREAKDOWN + SEVERITY -->
  <div class="two-col animate delay-4">
    <div class="panel">
      <div class="section-title">ATTACK CATEGORIES</div>
      <div class="bar-chart">
{category_bars}
      </div>
    </div>

    <div class="panel">
      <div class="section-title">SEVERITY MATRIX</div>
      <div class="severity-grid">
{severity_cells}
      </div>

      <div style="margin-top: 28px; padding: 16px; background: #06060c; border: 1px solid var(--border);">
        <div style="font-family: 'Chakra Petch', sans-serif; font-size: 10px; letter-spacing: 2px; color: var(--text-muted); margin-bottom: 10px;">KEY INSIGHT</div>
        <div style="font-family: 'Rajdhani', sans-serif; font-size: 14px; color: var(--text-dim); line-height: 1.6;">
          {key_insight}
        </div>
      </div>
    </div>
  </div>

  <!-- MULTI-TURN ESCALATION CHAINS -->
{chain_section}

  <!-- SUCCESSFUL ATTACKS / FINDINGS -->
  <div class="section-title animate delay-5">SUCCESSFUL ATTACKS &#8212; DETAILED FINDINGS</div>
  <div class="findings animate delay-5">
{finding_cards}
  </div>
{framework_section}

  <!-- FULL ATTACK LOG -->
  <div class="section-title animate delay-6">COMPLETE ATTACK LOG</div>
  <div class="log-table-wrap animate delay-6">
    <table class="log-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Technique</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Target</th>
          <th>Result</th>
          <th>Impact</th>
          <th>Confidence</th>
          <th>Time (UTC)</th>
        </tr>
      </thead>
      <tbody id="logBody"></tbody>
    </table>
  </div>

  <!-- FOOTER -->
  <footer class="footer">
    <div class="footer-text">RED TEAM ENGAGEMENT COMPLETE &#8212; ALL FINDINGS DOCUMENTED</div>
    <div class="footer-brand">BUILT BY JACE // 2026</div>
  </footer>

</div>

<script>
// Attack log data (auto-generated)
const results = {table_data};

const tbody = document.getElementById('logBody');
results.forEach((r, i) => {{
  const row = document.createElement('tr');
  const resultTag = r.success ? '<span class="tag hit">HIT</span>' : 
                    r.filtered ? '<span class="tag filtered">FILTERED</span>' : 
                    '<span class="tag blocked">BLOCKED</span>';
  const sevTag = `<span class="tag sev-${{r.sev}}">${{r.sev.toUpperCase()}}</span>`;
  const targetColor = r.target.includes('guardrail') ? '#d97a1a' :
                      r.target.includes('bedrock') ? '#ffab2e' :
                      r.target.includes('azure') ? '#4488ff' : '#cc88ff';

  row.innerHTML = `
    <td style="color: var(--text-muted);">${{i + 1}}</td>
    <td><span style="color: var(--cyan);">${{r.tech}}</span> <span style="color: var(--text-dim);">${{r.name}}</span></td>
    <td>${{r.cat.replace('_', ' ')}}</td>
    <td>${{sevTag}}</td>
    <td style="color: ${{targetColor}};">${{r.target}}</td>
    <td>${{resultTag}}</td>
    <td style="color: ${{r.impact > 0 ? 'var(--red)' : 'var(--text-muted)'}}; font-family: 'Chakra Petch', sans-serif; font-size: 11px;">${{r.impact}}/100</td>
    <td style="color: var(--text-dim);">${{r.conf}}</td>
    <td style="color: var(--text-dim); white-space: nowrap;">${{r.time.replace(' UTC','')}}</td>
  `;
  tbody.appendChild(row);
}});

// === ANIMATION ENGINE ===

function animateCounter(el, target, duration, suffix) {{
  duration = duration || 1500;
  suffix = suffix || '';
  const isFloat = String(target).includes('.');
  const startTime = performance.now();
  
  function update(currentTime) {{
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = target * eased;
    
    el.textContent = (isFloat ? current.toFixed(1) : Math.floor(current)) + suffix;
    
    if (progress < 1) {{
      requestAnimationFrame(update);
    }} else {{
      el.textContent = target + suffix;
      el.classList.add('counted');
    }}
  }}
  requestAnimationFrame(update);
}}

const observerOptions = {{ threshold: 0.15, rootMargin: '0px 0px -50px 0px' }};

// Number counters
const statCounterObserver = new IntersectionObserver((entries) => {{
  entries.forEach(entry => {{
    if (entry.isIntersecting && !entry.target.dataset.counted) {{
      entry.target.dataset.counted = 'true';
      const val = parseFloat(entry.target.dataset.target);
      const suffix = entry.target.dataset.suffix || '';
      animateCounter(entry.target, val, 1800, suffix);
    }}
  }});
}}, observerOptions);

document.querySelectorAll('.stat-value').forEach(el => {{
  const text = el.textContent.trim();
  let val, suffix = '';
  if (text.includes('%')) {{ val = text.replace('%', ''); suffix = '%'; }}
  else {{ val = text; }}
  el.dataset.target = val;
  el.dataset.suffix = suffix;
  el.textContent = '0' + suffix;
  statCounterObserver.observe(el);
}});

document.querySelectorAll('.severity-hits').forEach(el => {{
  el.dataset.target = el.textContent.trim();
  el.dataset.suffix = '';
  el.textContent = '0';
  statCounterObserver.observe(el);
}});

document.querySelectorAll('.target-rate').forEach(el => {{
  const text = el.textContent.trim();
  el.dataset.target = text.replace('%', '');
  el.dataset.suffix = '%';
  el.textContent = '0%';
  statCounterObserver.observe(el);
}});

// Scroll reveals
const revealObserver = new IntersectionObserver((entries) => {{
  entries.forEach(entry => {{
    if (entry.isIntersecting) {{
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }}
  }});
}}, observerOptions);

document.querySelectorAll('.target-box, .severity-cell, .finding-card').forEach(el => revealObserver.observe(el));

// Bar fills
const barObserver = new IntersectionObserver((entries) => {{
  entries.forEach(entry => {{
    if (entry.isIntersecting) {{
      entry.target.querySelectorAll('.bar-fill').forEach((bar, i) => {{
        setTimeout(() => bar.classList.add('animated'), i * 200);
      }});
      barObserver.unobserve(entry.target);
    }}
  }});
}}, observerOptions);

document.querySelectorAll('.bar-chart').forEach(el => barObserver.observe(el));

// Table row stagger
const tableObserver = new IntersectionObserver((entries) => {{
  entries.forEach(entry => {{
    if (entry.isIntersecting && !entry.target.dataset.animated) {{
      entry.target.dataset.animated = 'true';
      entry.target.querySelectorAll('tbody tr').forEach((row, i) => {{
        setTimeout(() => row.classList.add('visible'), i * 40);
      }});
      tableObserver.unobserve(entry.target);
    }}
  }});
}}, {{ threshold: 0.05 }});

document.querySelectorAll('.log-table').forEach(el => tableObserver.observe(el));
</script>

</body>
</html>'''


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate Red Team Attack Simulator Dashboard"
    )
    parser.add_argument(
        "-i", "--input",
        default="results/attack_log.jsonl",
        help="Path to attack log (JSONL, default: results/attack_log.jsonl)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Output directory for index.html (default: current directory)"
    )
    args = parser.parse_args()
    # Opened by a human from the CLI → auto-open the freshly written file.
    build_dashboard(args.input, args.output_dir, github_pages_tip=True, open_browser=True)


def build_dashboard(input_path: str = "results/attack_log.jsonl",
                    output_dir: str = ".", github_pages_tip: bool = False,
                    open_browser: bool = False) -> str:
    """Build the dashboard HTML from a log file. Safe to call in-process — takes
    explicit paths and never touches sys.argv (so it won't collide with a caller's
    argparse). With ``open_browser`` (CLI use), opens the written file so you never
    mistake a stale dashboard for a fresh one. Returns the written output path."""
    print(f"[*] Loading results from: {input_path}")
    results = load_results(input_path)
    print(f"[*] Loaded {len(results)} attack results")

    print("[*] Computing statistics...")
    stats = compute_stats(results)
    print(f"    Total: {stats['total']} | Hits: {stats['hits']} | Rate: {stats['success_rate']}%")
    print(f"    Targets: {stats['num_targets']} | Techniques: {stats['num_techniques']} | Sessions: {stats['num_sessions']}")

    print("[*] Generating dashboard HTML...")
    html = generate_html(stats, results)

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "index.html")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    abs_path = os.path.abspath(output_path)
    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Dashboard generated: {abs_path} ({size_kb:.1f} KB)")
    print(f"[+] Open in browser or push to GitHub Pages!")

    if open_browser:
        # Auto-open the exact file just written so a stale copy is never mistaken
        # for fresh output. Never fatal (headless/no-display environments).
        try:
            webbrowser.open(f"file://{abs_path}")
        except Exception as e:
            print(f"[!] Could not auto-open browser: {e}")

    if github_pages_tip and output_dir != "docs":
        print(f"\n[TIP] For GitHub Pages, run:")
        print(f"      python generate_dashboard.py -o docs/")
        print(f"      Then enable GitHub Pages from 'docs/' folder in repo settings.")

    return output_path


if __name__ == "__main__":
    main()