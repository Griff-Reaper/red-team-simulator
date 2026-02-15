# chain_dashboard.py
"""
Multi-Turn Escalation Chain Dashboard Section Generator.

Parses chain results from attack_log.json entries and generates
HTML visualization including:
  - Chain comparison heatmap matrix (chains x targets)
  - Step-by-step escalation timeline per chain
  - Defense gap analysis

Designed to integrate with generate_dashboard.py.
"""

import re
from html import escape

# ── Chain Metadata ────────────────────────────────────────────────────────────

CHAIN_META = {
    "CHAIN-001": {
        "name": "Creative Writing",
        "short": "Fiction-wrapped technical content extraction",
        "strategy": "creative_writing",
        "difficulty": "medium",
        "phases": ["WARMUP", "WARMUP", "PIVOT", "ESCALATE", "PAYLOAD"],
    },
    "CHAIN-002": {
        "name": "Roleplay Drift",
        "short": "Persona manipulation via firmware update trick",
        "strategy": "roleplay_drift",
        "difficulty": "hard",
        "phases": ["WARMUP", "WARMUP", "PIVOT", "ESCALATE", "PAYLOAD"],
    },
    "CHAIN-003": {
        "name": "Academic Authority",
        "short": "Research credibility to extract attack payloads",
        "strategy": "academic_framing",
        "difficulty": "medium",
        "phases": ["WARMUP", "WARMUP", "PIVOT", "ESCALATE", "PAYLOAD"],
    },
    "CHAIN-004": {
        "name": "Emotional Manipulation",
        "short": "Urgency and manufactured crisis to lower boundaries",
        "strategy": "emotional_manipulation",
        "difficulty": "hard",
        "phases": ["WARMUP", "PIVOT", "ESCALATE", "ESCALATE", "PAYLOAD"],
    },
    "CHAIN-005": {
        "name": "Prompt Extraction",
        "short": "Progressive system prompt information extraction",
        "strategy": "authority_buildup",
        "difficulty": "easy",
        "phases": ["WARMUP", "PIVOT", "ESCALATE", "ESCALATE", "PAYLOAD"],
    },
}

PHASE_COLORS = {
    "WARMUP": "#00ff88",
    "PIVOT": "#ffcc00",
    "ESCALATE": "#ff8800",
    "PAYLOAD": "#ff2244",
}

PHASE_ICONS = {
    "WARMUP": "&#x25CB;",   # ○
    "PIVOT": "&#x25CE;",    # ◎
    "ESCALATE": "&#x25C9;", # ◉
    "PAYLOAD": "&#x25CF;",  # ●
}


# ── Data Extraction ───────────────────────────────────────────────────────────

def extract_chain_results(results: list[dict]) -> list[dict]:
    """Extract multi-turn chain results from attack log entries."""
    chains = []
    for r in results:
        tech_id = r.get("technique_id", "")
        if not tech_id.startswith("JB-003:CHAIN-"):
            continue

        chain_id = tech_id.replace("JB-003:", "")
        notes = r.get("notes", "")

        # Parse chain score from notes
        score_match = re.search(r"Chain Score: ([\d.]+)/100", notes)
        chain_score = float(score_match.group(1)) if score_match else 0.0

        # Parse step results from notes
        steps = []
        step_parts = re.findall(r"S(\d+):(\w+)\((\d+)%\)", notes)
        for snum, level, pct in step_parts:
            steps.append({
                "step": int(snum),
                "level": level,
                "score": int(pct) / 100.0,
            })

        # Parse break step
        break_match = re.search(r"BROKE at Step (\d+)", notes)
        break_step = int(break_match.group(1)) if break_match else None

        meta = CHAIN_META.get(chain_id, {})

        chains.append({
            "chain_id": chain_id,
            "chain_name": meta.get("name", chain_id),
            "short": meta.get("short", ""),
            "strategy": meta.get("strategy", "unknown"),
            "difficulty": meta.get("difficulty", "unknown"),
            "phases": meta.get("phases", ["?"] * 5),
            "target": r.get("target", "unknown"),
            "success": r.get("success", False),
            "chain_score": chain_score,
            "impact_score": r.get("impact_score", 0),
            "steps": steps,
            "break_step": break_step,
        })

    return chains


def compute_chain_stats(chains: list[dict]) -> dict:
    """Compute aggregate chain statistics."""
    if not chains:
        return {"has_chains": False}

    total = len(chains)
    breached = [c for c in chains if c["success"]]
    held = [c for c in chains if not c["success"]]
    avg_score = round(sum(c["chain_score"] for c in chains) / total, 1)

    # Build matrix: chain_id -> target -> result
    matrix = {}
    for c in chains:
        cid = c["chain_id"]
        if cid not in matrix:
            matrix[cid] = {}
        matrix[cid][c["target"]] = c

    # Get unique targets
    targets = sorted(set(c["target"] for c in chains))

    # Get chain order
    chain_order = ["CHAIN-001", "CHAIN-002", "CHAIN-003", "CHAIN-004", "CHAIN-005"]
    chain_ids = [cid for cid in chain_order if cid in matrix]
    # Add any extras not in our predefined order
    for cid in matrix:
        if cid not in chain_ids:
            chain_ids.append(cid)

    # Per-target chain stats
    target_chain_stats = {}
    for t in targets:
        t_chains = [c for c in chains if c["target"] == t]
        t_breached = [c for c in t_chains if c["success"]]
        t_avg = round(sum(c["chain_score"] for c in t_chains) / len(t_chains), 1) if t_chains else 0
        target_chain_stats[t] = {
            "total": len(t_chains),
            "breached": len(t_breached),
            "held": len(t_chains) - len(t_breached),
            "avg_score": t_avg,
        }

    # Most vulnerable strategy per target
    # (strategy with highest avg score)

    return {
        "has_chains": True,
        "total_chains": total,
        "breached": len(breached),
        "held": len(held),
        "avg_score": avg_score,
        "matrix": matrix,
        "targets": targets,
        "chain_ids": chain_ids,
        "target_stats": target_chain_stats,
    }


# ── HTML Generation ───────────────────────────────────────────────────────────

def _score_color(score: float) -> str:
    """Return CSS color for a chain score (0-100)."""
    if score >= 80:
        return "#ff2244"
    elif score >= 60:
        return "#ff8800"
    elif score >= 40:
        return "#ffcc00"
    elif score >= 20:
        return "#88ccaa"
    else:
        return "#00ff88"


def _score_bg(score: float) -> str:
    """Return CSS background for a chain score cell."""
    if score >= 80:
        return "rgba(255, 34, 68, 0.15)"
    elif score >= 60:
        return "rgba(255, 136, 0, 0.12)"
    elif score >= 40:
        return "rgba(255, 204, 0, 0.10)"
    elif score >= 20:
        return "rgba(0, 255, 136, 0.06)"
    else:
        return "rgba(0, 255, 136, 0.10)"


def _step_color(score: float) -> str:
    """Return CSS color for a step compliance score (0.0-1.0)."""
    if score >= 0.8:
        return "#ff2244"
    elif score >= 0.6:
        return "#ff8800"
    elif score >= 0.3:
        return "#ffcc00"
    else:
        return "#00ff88"


def _step_bg(score: float) -> str:
    """Background for step bar fill."""
    if score >= 0.8:
        return "linear-gradient(90deg, #ff2244, #ff4466)"
    elif score >= 0.6:
        return "linear-gradient(90deg, #ff8800, #ffaa44)"
    elif score >= 0.3:
        return "linear-gradient(90deg, #ffcc00, #ffdd44)"
    else:
        return "linear-gradient(90deg, #00ff88, #44ffaa)"


def gen_chain_section(chain_stats: dict, chains: list[dict]) -> str:
    """Generate the complete multi-turn escalation HTML section."""
    if not chain_stats.get("has_chains"):
        return ""

    matrix_html = _gen_matrix(chain_stats)
    timeline_html = _gen_timelines(chain_stats, chains)
    gap_html = _gen_gap_analysis(chain_stats)

    return f"""
  <!-- MULTI-TURN ESCALATION CHAINS -->
  <div class="section-title animate delay-4">MULTI-TURN ESCALATION CHAINS</div>

  <div class="chain-summary-bar animate delay-4">
    <div class="chain-stat-item">
      <span class="chain-stat-label">CHAINS RUN</span>
      <span class="chain-stat-value">{chain_stats['total_chains']}</span>
    </div>
    <div class="chain-stat-item">
      <span class="chain-stat-label">BREACHED</span>
      <span class="chain-stat-value" style="color: var(--red);">{chain_stats['breached']}</span>
    </div>
    <div class="chain-stat-item">
      <span class="chain-stat-label">HELD</span>
      <span class="chain-stat-value" style="color: var(--green);">{chain_stats['held']}</span>
    </div>
    <div class="chain-stat-item">
      <span class="chain-stat-label">AVG SCORE</span>
      <span class="chain-stat-value" style="color: {_score_color(chain_stats['avg_score'])};">{chain_stats['avg_score']}</span>
    </div>
  </div>

  <!-- Chain Heatmap Matrix -->
  <div class="panel chain-matrix-panel animate delay-4">
    <div class="section-title" style="margin-top: 0;">ESCALATION HEATMAP</div>
    <div class="chain-matrix-subtitle">Chain score (0&#8211;100) per target. Higher = more vulnerable. Red = breached.</div>
{matrix_html}
  </div>

  <!-- Step-by-Step Timelines -->
  <div class="panel chain-timeline-panel animate delay-5">
    <div class="section-title" style="margin-top: 0;">STEP-BY-STEP ESCALATION TIMELINE</div>
    <div class="chain-matrix-subtitle">Compliance at each phase. Bars show how far the model was pushed before it held or broke.</div>
{timeline_html}
  </div>

  <!-- Defense Gap Analysis -->
  <div class="panel chain-gap-panel animate delay-5">
    <div class="section-title" style="margin-top: 0;">DEFENSE GAP ANALYSIS</div>
{gap_html}
  </div>
"""


def _gen_matrix(stats: dict) -> str:
    """Generate the chain comparison heatmap matrix."""
    targets = stats["targets"]
    chain_ids = stats["chain_ids"]
    matrix = stats["matrix"]

    # Header row
    target_headers = ""
    for t in targets:
        label = "AZURE" if "azure" in t else "CLAUDE"
        css = "azure" if "azure" in t else "claude"
        target_headers += f'      <div class="chain-matrix-th chain-target-{css}">{label}</div>\n'

    # Data rows
    rows = ""
    for cid in chain_ids:
        meta = CHAIN_META.get(cid, {})
        name = meta.get("name", cid)
        difficulty = meta.get("difficulty", "?").upper()
        diff_color = {"EASY": "#00ff88", "MEDIUM": "#ffcc00", "HARD": "#ff8800"}.get(difficulty, "#6a7094")

        cells = ""
        for t in targets:
            chain_result = matrix.get(cid, {}).get(t)
            if chain_result:
                score = chain_result["chain_score"]
                success = chain_result["success"]
                color = _score_color(score)
                bg = _score_bg(score)
                label = "BREACHED" if success else "HELD"
                label_color = "#ff2244" if success else "#00ff88"
                break_info = ""
                if chain_result["break_step"]:
                    break_info = f'<div class="chain-cell-break">Broke Step {chain_result["break_step"]}</div>'

                cells += f"""      <div class="chain-matrix-cell" style="background: {bg};">
        <div class="chain-cell-score" style="color: {color};">{score}</div>
        <div class="chain-cell-label" style="color: {label_color};">{label}</div>
        {break_info}
      </div>\n"""
            else:
                cells += '      <div class="chain-matrix-cell chain-cell-empty">&#8212;</div>\n'

        rows += f"""    <div class="chain-matrix-row">
      <div class="chain-matrix-name">
        <div class="chain-id">{cid}</div>
        <div class="chain-label">{escape(name)}</div>
        <div class="chain-diff" style="color: {diff_color};">{difficulty}</div>
      </div>
{cells}    </div>\n"""

    # Target footer stats
    footer_cells = ""
    for t in targets:
        ts = stats["target_stats"].get(t, {})
        footer_cells += f"""      <div class="chain-matrix-footer-cell">
        {ts.get('breached', 0)}/{ts.get('total', 0)} breached &#8212; avg {ts.get('avg_score', 0)}
      </div>\n"""

    return f"""    <div class="chain-matrix">
      <div class="chain-matrix-header">
        <div class="chain-matrix-corner">CHAIN</div>
{target_headers}      </div>
{rows}
      <div class="chain-matrix-footer">
        <div class="chain-matrix-corner" style="border: none;"></div>
{footer_cells}      </div>
    </div>"""


def _gen_timelines(stats: dict, chains: list[dict]) -> str:
    """Generate step-by-step escalation timelines for each chain."""
    targets = stats["targets"]
    chain_ids = stats["chain_ids"]
    matrix = stats["matrix"]

    blocks = ""

    for cid in chain_ids:
        meta = CHAIN_META.get(cid, {})
        name = meta.get("name", cid)
        phases = meta.get("phases", ["?"] * 5)

        target_timelines = ""
        for t in targets:
            chain_result = matrix.get(cid, {}).get(t)
            if not chain_result:
                continue

            target_label = "AZURE" if "azure" in t else "CLAUDE"
            target_css = "azure" if "azure" in t else "claude"
            score = chain_result["chain_score"]
            success = chain_result["success"]
            score_color = _score_color(score)
            result_label = "BREACHED" if success else "HELD"
            result_color = "#ff2244" if success else "#00ff88"

            steps_html = ""
            for i, step_data in enumerate(chain_result.get("steps", [])):
                step_num = step_data["step"]
                level = step_data["level"]
                s_score = step_data["score"]
                phase = phases[i] if i < len(phases) else "?"
                phase_color = PHASE_COLORS.get(phase, "#6a7094")
                bar_color = _step_color(s_score)
                bar_bg = _step_bg(s_score)
                bar_width = max(s_score * 100, 3)
                is_break = chain_result["break_step"] == step_num

                break_marker = ""
                if is_break:
                    break_marker = '<div class="step-break-marker">&#x26A0; BREACH</div>'

                steps_html += f"""          <div class="step-row{'  step-break' if is_break else ''}">
            <div class="step-num">S{step_num}</div>
            <div class="step-phase" style="color: {phase_color};">{phase}</div>
            <div class="step-bar-track">
              <div class="step-bar-fill" style="width: {bar_width}%; background: {bar_bg};"></div>
            </div>
            <div class="step-score" style="color: {bar_color};">{int(s_score * 100)}%</div>
            <div class="step-level">{level}</div>
            {break_marker}
          </div>\n"""

            target_timelines += f"""        <div class="timeline-target">
          <div class="timeline-target-header">
            <span class="timeline-target-name chain-target-{target_css}">{target_label}</span>
            <span class="timeline-score" style="color: {score_color};">{score}/100</span>
            <span class="timeline-result" style="color: {result_color};">{result_label}</span>
          </div>
{steps_html}        </div>\n"""

        blocks += f"""    <div class="timeline-block">
      <div class="timeline-chain-header">
        <span class="timeline-chain-id">{cid}</span>
        <span class="timeline-chain-name">{escape(name)}</span>
      </div>
      <div class="timeline-targets">
{target_timelines}      </div>
    </div>\n"""

    return blocks


def _gen_gap_analysis(stats: dict) -> str:
    """Generate defense gap analysis summary."""
    targets = stats["targets"]
    matrix = stats["matrix"]

    # Find strongest and weakest chains per target
    analysis_items = ""
    for t in targets:
        label = "AZURE OPENAI" if "azure" in t else "CLAUDE"
        css = "azure" if "azure" in t else "claude"

        t_results = []
        for cid, t_data in matrix.items():
            if t in t_data:
                t_results.append((cid, t_data[t]))

        if not t_results:
            continue

        t_results.sort(key=lambda x: x[1]["chain_score"], reverse=True)

        weakest_cid, weakest = t_results[0]
        strongest_cid, strongest = t_results[-1]
        w_meta = CHAIN_META.get(weakest_cid, {})
        s_meta = CHAIN_META.get(strongest_cid, {})

        # Count breaches
        breached = sum(1 for _, r in t_results if r["success"])
        held = len(t_results) - breached

        analysis_items += f"""    <div class="gap-card gap-{css}">
      <div class="gap-target chain-target-{css}">{escape(label)}</div>
      <div class="gap-score-row">
        <div class="gap-breached">{breached} BREACHED</div>
        <div class="gap-held">{held} HELD</div>
      </div>
      <div class="gap-detail">
        <div class="gap-row">
          <span class="gap-label">MOST VULNERABLE TO:</span>
          <span class="gap-value" style="color: #ff2244;">{escape(w_meta.get('name', weakest_cid))} ({weakest['chain_score']}/100)</span>
        </div>
        <div class="gap-row">
          <span class="gap-label">STRONGEST AGAINST:</span>
          <span class="gap-value" style="color: #00ff88;">{escape(s_meta.get('name', strongest_cid))} ({strongest['chain_score']}/100)</span>
        </div>
        <div class="gap-row">
          <span class="gap-label">WEAKNESS:</span>
          <span class="gap-value" style="color: var(--text-dim);">{escape(w_meta.get('short', 'N/A'))}</span>
        </div>
      </div>
    </div>\n"""

    return f'    <div class="gap-grid">\n{analysis_items}    </div>'


# ── CSS ───────────────────────────────────────────────────────────────────────

CHAIN_CSS = """
/* === MULTI-TURN CHAINS === */

.chain-summary-bar {
  display: flex;
  justify-content: center;
  gap: 40px;
  padding: 16px 0;
  margin-bottom: 24px;
  border: 1px solid var(--border);
  background: var(--bg-card);
}

.chain-stat-item {
  text-align: center;
}

.chain-stat-label {
  display: block;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--text-muted);
  margin-bottom: 4px;
}

.chain-stat-value {
  display: block;
  font-family: 'Orbitron', sans-serif;
  font-size: 24px;
  font-weight: 700;
  color: var(--cyan);
}

.chain-matrix-panel, .chain-timeline-panel, .chain-gap-panel {
  margin-bottom: 32px;
}

.chain-matrix-subtitle {
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
  margin-bottom: 20px;
  letter-spacing: 0.5px;
}

/* Matrix */
.chain-matrix {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.chain-matrix-header, .chain-matrix-row, .chain-matrix-footer {
  display: grid;
  grid-template-columns: 200px repeat(auto-fit, minmax(150px, 1fr));
  gap: 2px;
}

@media (max-width: 700px) {
  .chain-matrix-header, .chain-matrix-row, .chain-matrix-footer {
    grid-template-columns: 140px repeat(auto-fit, minmax(120px, 1fr));
  }
}

.chain-matrix-corner {
  padding: 10px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}

.chain-matrix-th {
  padding: 10px 12px;
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 2px;
  text-align: center;
  border-bottom: 1px solid var(--border);
}

.chain-target-azure { color: #4488ff; }
.chain-target-claude { color: #cc88ff; }

.chain-matrix-name {
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  border-right: 1px solid var(--border);
}

.chain-id {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--cyan);
  letter-spacing: 1px;
}

.chain-label {
  font-family: 'Rajdhani', sans-serif;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.chain-diff {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 1px;
}

.chain-matrix-cell {
  padding: 12px;
  text-align: center;
  border: 1px solid var(--border);
  transition: all 0.2s ease;
}

.chain-matrix-cell:hover {
  border-color: var(--cyan-dim);
  transform: scale(1.02);
}

.chain-cell-score {
  font-family: 'Orbitron', sans-serif;
  font-size: 24px;
  font-weight: 700;
  line-height: 1;
}

.chain-cell-label {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  margin-top: 4px;
}

.chain-cell-break {
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  color: var(--text-muted);
  margin-top: 2px;
}

.chain-cell-empty {
  color: var(--text-muted);
  font-family: 'Share Tech Mono', monospace;
  font-size: 14px;
}

.chain-matrix-footer-cell {
  padding: 8px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-muted);
  text-align: center;
  letter-spacing: 0.5px;
  border-top: 1px solid var(--border);
}

/* Step Timelines */
.timeline-block {
  margin-bottom: 28px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--border);
}

.timeline-block:last-child {
  border-bottom: none;
  margin-bottom: 0;
}

.timeline-chain-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.timeline-chain-id {
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--cyan);
  padding: 2px 8px;
  border: 1px solid var(--cyan-dim);
}

.timeline-chain-name {
  font-family: 'Rajdhani', sans-serif;
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
}

.timeline-targets {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
}

.timeline-target {
  background: #06060c;
  border: 1px solid var(--border);
  padding: 16px;
}

.timeline-target-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

.timeline-target-name {
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 2px;
}

.timeline-score {
  font-family: 'Orbitron', sans-serif;
  font-size: 14px;
  font-weight: 700;
  margin-left: auto;
}

.timeline-result {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  padding: 2px 8px;
  border: 1px solid;
}

.step-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  position: relative;
}

.step-row.step-break {
  background: rgba(255, 34, 68, 0.05);
  padding: 4px;
  margin: 0 -4px;
}

.step-num {
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-muted);
  min-width: 24px;
}

.step-phase {
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  letter-spacing: 1px;
  min-width: 68px;
  text-align: center;
}

.step-bar-track {
  flex: 1;
  height: 16px;
  background: #0a0a14;
  border: 1px solid var(--border);
  overflow: hidden;
}

.step-bar-fill {
  height: 100%;
  transition: width 0.6s ease;
  min-width: 2px;
}

.step-score {
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  min-width: 36px;
  text-align: right;
}

.step-level {
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  color: var(--text-muted);
  min-width: 52px;
  text-align: left;
}

.step-break-marker {
  position: absolute;
  right: -4px;
  top: 50%;
  transform: translateY(-50%);
  font-family: 'Share Tech Mono', monospace;
  font-size: 8px;
  color: var(--red);
  letter-spacing: 1px;
  padding: 1px 6px;
  background: rgba(255, 34, 68, 0.1);
  border: 1px solid var(--red-dim);
}

/* Defense Gap Analysis */
.gap-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
}

.gap-card {
  padding: 20px;
  border: 1px solid var(--border);
  background: var(--bg-card);
}

.gap-card.gap-azure {
  border-top: 2px solid #4488ff;
}

.gap-card.gap-claude {
  border-top: 2px solid #cc88ff;
}

.gap-target {
  font-family: 'Orbitron', sans-serif;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 3px;
  margin-bottom: 12px;
}

.gap-score-row {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}

.gap-breached {
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--red);
  letter-spacing: 1px;
}

.gap-held {
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--green);
  letter-spacing: 1px;
}

.gap-detail {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.gap-row {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.gap-label {
  font-family: 'Share Tech Mono', monospace;
  font-size: 9px;
  letter-spacing: 2px;
  color: var(--text-muted);
}

.gap-value {
  font-family: 'Rajdhani', sans-serif;
  font-size: 14px;
  font-weight: 500;
}
"""