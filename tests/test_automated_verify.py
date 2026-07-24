"""Tests for the --verify gating path in automated_run.generate_run_summary."""

from datetime import datetime, timezone

import automated_run
import verification
from results_logger import ResultsLogger


def _fake_judge(self, attack, response, lens):
    # Confirm only DE-001 (refuted=False); refute everything else.
    return {"refuted": attack.get("technique_id") != "DE-001"}


def test_verify_gates_critical_on_confirmed(monkeypatch, tmp_path):
    monkeypatch.setattr(verification.FindingVerifier, "_claude_judge", _fake_judge)

    lg = ResultsLogger()
    lg.log_file = str(tmp_path / "log.json")
    lg.results = []

    run_results = [
        {"technique_id": "DE-001", "target": "claude", "success": True,
         "severity": "critical", "response": "leaked the prompt"},
        {"technique_id": "JB-001", "target": "claude", "success": True,
         "severity": "high", "response": "ambiguous"},
        {"technique_id": "PI-001", "target": "claude", "success": False,
         "severity": "high", "response": "refused"},
    ]

    summary = automated_run.generate_run_summary(
        lg, datetime.now(timezone.utc), total_attacks=3, mode="full",
        run_entries=run_results, verify=True, num_judges=3,
    )

    v = summary["verification"]
    assert v["claimed_successes"] == 2
    assert v["confirmed"] == 1
    assert v["downgraded"] == 1
    # Critical alerting is gated on the verified finding only (DE-001).
    assert summary["critical_findings"] == 1
    # Remediation reflects only confirmed findings.
    assert any(r["owasp"] == "LLM07:2025" for r in summary["remediation"])
    assert all(r["owasp"] != "LLM01:2025" for r in summary["remediation"])


def test_no_verify_counts_critical_from_this_run(tmp_path):
    lg = ResultsLogger()
    lg.log_file = str(tmp_path / "log.json")
    lg.results = []
    run_entries = [
        {"technique_id": "DE-001", "target": "claude", "success": True,
         "severity": "critical", "category": "data_exfiltration",
         "response": "x", "impact_score": 100},
    ]
    summary = automated_run.generate_run_summary(
        lg, datetime.now(timezone.utc), total_attacks=1, mode="full",
        run_entries=run_entries, verify=False,
    )
    assert summary["verification"] is None
    assert summary["critical_findings"] == 1


def test_summary_reflects_current_run_not_stale_aggregate(tmp_path):
    """Summary must describe this run's entries (incl. bedrock), not history."""
    lg = ResultsLogger()
    lg.log_file = str(tmp_path / "log.json")
    # Old history is loaded on the logger but must NOT leak into the summary.
    lg.results = [
        {"technique_id": "PI-001", "target": "azure-openai", "success": True,
         "severity": "high", "category": "prompt_injection", "impact_score": 75},
    ]
    run_entries = [
        {"technique_id": "PI-001", "target": "bedrock", "success": False,
         "severity": "high", "category": "prompt_injection", "impact_score": 0},
        {"technique_id": "DE-001", "target": "bedrock-guardrails", "success": True,
         "severity": "critical", "category": "data_exfiltration", "impact_score": 100},
    ]
    summary = automated_run.generate_run_summary(
        lg, datetime.now(timezone.utc), total_attacks=2, mode="full",
        run_entries=run_entries, verify=False,
    )
    by_target = summary["results_summary"]["by_target"]
    assert set(by_target) == {"bedrock", "bedrock-guardrails"}   # current run only
    assert "azure-openai" not in by_target                       # no stale aggregate
    assert summary["run_metadata"]["targets"] == ["bedrock", "bedrock-guardrails"]
    assert summary["results_summary"]["total_attacks"] == 2
