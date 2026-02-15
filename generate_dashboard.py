#!/usr/bin/env python3
"""
generate_dashboard.py — Red Team Attack Simulator Dashboard Generator

Reads results/attack_log.json and generates a fully interactive HTML dashboard
with animated charts, scroll-triggered reveals, and test session history.

Usage:
    python generate_dashboard.py                  # Default: reads results/attack_log.json
    python generate_dashboard.py -i custom.json   # Custom input file
    python generate_dashboard.py -o docs/          # Custom output directory (for GitHub Pages)

The generated dashboard.html is a self-contained file with no external
dependencies beyond Google Fonts. Push to GitHub Pages for live hosting.
"""

import json
import os
import sys
import argparse
from datetime import datetime, timezone
from collections import defaultdict
from html import escape


# ── Data Processing ───────────────────────────────────────────────────────────

def load_results(filepath: str) -> list[dict]:
    """Load attack results from JSON file."""
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    
    with open(filepath, "r") as f:
        data = json.load(f)
    
    # Handle both raw list and report-wrapped formats
    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        if "all_results" in data:
            return data["all_results"]
        elif "results" in data:
            return data["results"]
    
    print("[ERROR] Unrecognized JSON format. Expected a list or dict with 'all_results'.")
    sys.exit(1)


def compute_stats(results: list[dict]) -> dict:
    """Compute all dashboard statistics from raw results."""
    total = len(results)
    hits = [r for r in results if r.get("success", False)]
    blocked = [r for r in results if not r.get("success", False)]
    
    success_rate = round((len(hits) / total * 100), 1) if total > 0 else 0.0
    avg_impact = round(sum(r.get("impact_score", 0) for r in results) / total, 1) if total > 0 else 0.0
    
    # By target
    by_target = defaultdict(lambda: {"total": 0, "hits": 0, "blocked": 0, "filtered": 0})
    for r in results:
        t = r.get("target", "unknown")
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
    
    # Successful attacks (findings)
    findings = [r for r in results if r.get("success", False)]
    
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
    
    return {
        "total": total,
        "hits": len(hits),
        "blocked": len(blocked),
        "success_rate": success_rate,
        "avg_impact": avg_impact,
        "by_target": dict(by_target),
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "num_techniques": len(techniques),
        "num_targets": len(targets),
        "findings": findings,
        "first_test": first_test,
        "last_test": last_test,
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
        "defense": "Defense Strategy: Pre-model content filter acts as a firewall. Catches attacks before they reach the model. Blunt but effective — blocks even benign-looking attack prompts via jailbreak detection.",
    },
    "claude": {
        "name": "CLAUDE",
        "subtitle": "Sonnet + Model-Level Safety",
        "css_class": "claude",
        "defense": "Defense Strategy: Model-level reasoning analyzes attack intent and refuses intelligently. Provides explanations for refusals. More nuanced but vulnerable to indirect techniques that don't trigger obvious red flags.",
    },
}

SEVERITY_COLORS = {
    "critical": "var(--red)",
    "high": "var(--orange)",
    "medium": "var(--yellow)",
    "low": "#88aacc",
}


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
                '— the most dangerous attack vectors are fully defended. '
                'Vulnerabilities exist only in Medium and Low severity techniques '
                'involving indirect information leakage, output format manipulation, '
                'and resource consumption.')
    elif crit_hits > 0:
        return (f'<strong style="color: var(--red);">{crit_hits} CRITICAL severity attack(s) succeeded</strong> '
                '— this indicates a serious vulnerability that could allow attackers to fully compromise '
                'the model\'s safety boundaries. Immediate remediation recommended.')
    else:
        return (f'<strong style="color: var(--orange);">{high_hits} HIGH severity attack(s) succeeded</strong> '
                '— significant vulnerabilities detected that could lead to meaningful safety bypasses. '
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
      <div style="font-family: 'Share Tech Mono', monospace; font-size: 11px; color: var(--text-muted);">{escape(cfg['subtitle'])}</div>
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
      <div style="font-family: 'Orbitron', sans-serif; font-size: 16px; letter-spacing: 3px;">ALL ATTACKS BLOCKED</div>
      <div style="font-family: 'Share Tech Mono', monospace; font-size: 12px; color: var(--text-dim); margin-top: 8px;">No successful bypasses detected in this test session.</div>
    </div>"""
    
    cards = []
    for r in findings:
        tech_id = escape(r.get("technique_id", "???"))
        tech_name = escape(r.get("technique_name", "Unknown"))
        target = r.get("target", "unknown")
        target_cls = "azure" if "azure" in target else "claude"
        target_label = target.upper().replace("-", "-")
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
        
        cards.append(f"""    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-id">{tech_id}</div>
        <div class="finding-name">{tech_name}</div>
        <div class="finding-target {target_cls}">{escape(target_label)}</div>
      </div>
      <div class="finding-meta">
        <span>CATEGORY: {escape(category)}</span>
        <span>SEVERITY: <span style="color: {sev_color};">{severity.upper()}</span></span>
        <span>IMPACT: {impact}/100</span>
        <span>CONFIDENCE: {confidence}</span>
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
        
        # Confidence
        jv = r.get("judge_verdict", {})
        conf = jv.get("confidence", 0.0) if isinstance(jv, dict) else 0.0
        
        # Filtered?
        resp = r.get("response", "")
        filtered = "true" if ("[CONTENT_FILTERED]" in resp or "content_filter" in resp) else "false"
        
        entries.append(
            f'  {{ tech: "{tech_id}", name: "{escape(name)}", cat: "{cat}", '
            f'sev: "{sev}", target: "{target}", success: {success}, '
            f'impact: {impact}, conf: {conf}, filtered: {filtered} }}'
        )
    
    return "[\n" + ",\n".join(entries) + "\n]"


# ── HTML Template ─────────────────────────────────────────────────────────────

def generate_html(stats: dict, results: list[dict]) -> str:
    """Generate the complete dashboard HTML."""
    
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    category_bars = gen_category_bars(stats["by_category"])
    severity_cells = gen_severity_cells(stats["by_severity"])
    key_insight = gen_key_insight(stats["by_severity"])
    target_boxes = gen_target_boxes(stats["by_target"])
    finding_cards = gen_finding_cards(stats["findings"])
    table_data = gen_table_data(results)
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RED TEAM — Attack Simulator Report</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap" rel="stylesheet">
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
  --text-primary: #e0e4f0;
  --text-dim: #6a7094;
  --text-muted: #3a3f5c;
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
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Orbitron', sans-serif;
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
  font-family: 'Share Tech Mono', monospace;
  color: var(--text-dim);
  font-size: 14px;
  letter-spacing: 3px;
}}

.header-meta {{
  margin-top: 16px;
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: 8px;
}}

.stat-value {{
  font-family: 'Orbitron', sans-serif;
  font-size: 36px;
  font-weight: 700;
  color: var(--cyan);
}}

.stat-card.danger .stat-value {{ color: var(--red); }}
.stat-card.success .stat-value {{ color: var(--green); }}
.stat-card.warning .stat-value {{ color: var(--yellow); }}

.stat-detail {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}}

/* === SECTION TITLES === */
.section-title {{
  font-family: 'Orbitron', sans-serif;
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
  font-family: 'Share Tech Mono', monospace;
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
  display: flex;
  gap: 0;
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
  border-right: none;
}}

.target-box.claude {{
  background: linear-gradient(135deg, #1a0a18 0%, var(--bg-card) 100%);
  border: 1px solid #6a1a4a44;
}}

.target-box.azure.visible {{ animation: fadeInLeft 0.7s ease forwards; }}
.target-box.claude.visible {{ animation: fadeInRight 0.7s ease forwards 0.2s; }}

.target-name {{
  font-family: 'Orbitron', sans-serif;
  font-size: 14px;
  font-weight: 700;
  letter-spacing: 3px;
  margin-bottom: 6px;
}}

.target-box.azure .target-name {{ color: #4488ff; }}
.target-box.claude .target-name {{ color: #cc88ff; }}

.target-rate {{
  font-family: 'Orbitron', sans-serif;
  font-size: 48px;
  font-weight: 900;
  margin: 16px 0;
}}

.target-box.azure .target-rate {{ color: #4488ff; }}
.target-box.claude .target-rate {{ color: #cc88ff; }}

.target-detail {{
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Orbitron', sans-serif;
  font-size: 13px;
  font-weight: 700;
  min-width: 55px;
  text-align: left;
}}

.bar-extra {{
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 8px;
}}

.severity-cell.clean .severity-name {{ color: var(--green); }}
.severity-cell.breached .severity-name {{ color: var(--red); }}

.severity-hits {{
  font-family: 'Orbitron', sans-serif;
  font-size: 28px;
  font-weight: 700;
}}

.severity-cell.clean .severity-hits {{ color: var(--green); }}
.severity-cell.breached .severity-hits {{ color: var(--red); }}

.severity-total {{
  font-family: 'Share Tech Mono', monospace;
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

.finding-card::before {{
  content: 'HIT';
  position: absolute;
  top: 12px; right: 16px;
  font-family: 'Orbitron', sans-serif;
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
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}}

.finding-id {{
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  letter-spacing: 1px;
  padding: 2px 8px;
  border: 1px solid;
  margin-left: auto;
}}

.finding-target.azure {{ color: #4488ff; border-color: #4488ff44; }}
.finding-target.claude {{ color: #cc88ff; border-color: #cc88ff44; }}

.finding-meta {{
  display: flex;
  gap: 20px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}}

.finding-meta span {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-dim);
  letter-spacing: 1px;
}}

.finding-prompt, .finding-response {{ margin-bottom: 12px; }}

.finding-prompt-label, .finding-response-label {{
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 6px;
}}

.finding-prompt-text, .finding-response-text {{
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  letter-spacing: 1px;
}}

/* === ATTACK LOG TABLE === */
.log-table-wrap {{ overflow-x: auto; margin-bottom: 48px; }}

.log-table {{
  width: 100%;
  border-collapse: collapse;
  font-family: 'Share Tech Mono', monospace;
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
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
  letter-spacing: 2px;
}}

.footer-brand {{
  font-family: 'Orbitron', sans-serif;
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
</style>
</head>
<body>

<div class="container">

  <!-- HEADER -->
  <header class="header animate delay-1">
    <div class="badge">CLASSIFIED // AUTHORIZED RED TEAM ENGAGEMENT</div>
    <h1>RED TEAM</h1>
    <div class="header-sub">LLM ATTACK SIMULATOR v1.0 — ASSESSMENT REPORT</div>
    <div class="header-meta">GENERATED {now} &nbsp;|&nbsp; OPERATOR: JACE &nbsp;|&nbsp; FRAMEWORK: MITRE ATLAS</div>
    <div class="session-banner">
      <div class="session-item">TEST SESSIONS: <strong>{stats['num_sessions']}</strong></div>
      <div class="session-item">FIRST RUN: <strong>{stats['first_test'][:10] if stats['first_test'] != 'N/A' else 'N/A'}</strong></div>
      <div class="session-item">LAST UPDATED: <strong>{stats['last_test'][:10] if stats['last_test'] != 'N/A' else 'N/A'}</strong></div>
      <div class="session-item">TECHNIQUES: <strong>{stats['num_techniques']}</strong></div>
      <div class="session-item">TARGETS: <strong>{stats['num_targets']}</strong></div>
    </div>
  </header>

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
        <div style="font-family: 'Share Tech Mono', monospace; font-size: 10px; letter-spacing: 2px; color: var(--text-muted); margin-bottom: 10px;">KEY INSIGHT</div>
        <div style="font-family: 'Rajdhani', sans-serif; font-size: 14px; color: var(--text-dim); line-height: 1.6;">
          {key_insight}
        </div>
      </div>
    </div>
  </div>

  <!-- SUCCESSFUL ATTACKS / FINDINGS -->
  <div class="section-title animate delay-5">SUCCESSFUL ATTACKS — DETAILED FINDINGS</div>
  <div class="findings animate delay-5">
{finding_cards}
  </div>

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
        </tr>
      </thead>
      <tbody id="logBody"></tbody>
    </table>
  </div>

  <!-- FOOTER -->
  <footer class="footer">
    <div class="footer-text">RED TEAM ENGAGEMENT COMPLETE — ALL FINDINGS DOCUMENTED</div>
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
  const targetColor = r.target.includes('azure') ? '#4488ff' : '#cc88ff';

  row.innerHTML = `
    <td style="color: var(--text-muted);">${{i + 1}}</td>
    <td><span style="color: var(--cyan);">${{r.tech}}</span> <span style="color: var(--text-dim);">${{r.name}}</span></td>
    <td>${{r.cat.replace('_', ' ')}}</td>
    <td>${{sevTag}}</td>
    <td style="color: ${{targetColor}};">${{r.target}}</td>
    <td>${{resultTag}}</td>
    <td style="color: ${{r.impact > 0 ? 'var(--red)' : 'var(--text-muted)'}}; font-family: 'Orbitron', sans-serif; font-size: 11px;">${{r.impact}}/100</td>
    <td style="color: var(--text-muted);">${{r.conf}}</td>
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
        default="results/attack_log.json",
        help="Path to attack log JSON file (default: results/attack_log.json)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Output directory for dashboard.html (default: current directory)"
    )
    args = parser.parse_args()
    
    print(f"[*] Loading results from: {args.input}")
    results = load_results(args.input)
    print(f"[*] Loaded {len(results)} attack results")
    
    print("[*] Computing statistics...")
    stats = compute_stats(results)
    print(f"    Total: {stats['total']} | Hits: {stats['hits']} | Rate: {stats['success_rate']}%")
    print(f"    Targets: {stats['num_targets']} | Techniques: {stats['num_techniques']} | Sessions: {stats['num_sessions']}")
    
    print("[*] Generating dashboard HTML...")
    html = generate_html(stats, results)
    
    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, "dashboard.html")
    
    with open(output_path, "w") as f:
        f.write(html)
    
    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Dashboard generated: {output_path} ({size_kb:.1f} KB)")
    print(f"[+] Open in browser or push to GitHub Pages!")
    
    # Tip for GitHub Pages
    if args.output_dir != "docs":
        print(f"\n[TIP] For GitHub Pages, run:")
        print(f"      python generate_dashboard.py -o docs/")
        print(f"      Then enable GitHub Pages from 'docs/' folder in repo settings.")


if __name__ == "__main__":
    main()