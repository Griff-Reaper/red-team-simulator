"""Tests for the remediation library (Strix-style mitigations)."""

from remediation import (
    REMEDIATIONS,
    remediation_for,
    remediations_for_findings,
    _owasp_for_technique_id,
)
from attack_taxonomy import ATTACK_TECHNIQUES


def test_every_used_owasp_category_has_remediation():
    used = {t.owasp for t in ATTACK_TECHNIQUES.values() if t.owasp}
    for owasp_id in used:
        assert owasp_id in REMEDIATIONS, f"no remediation for {owasp_id}"


def test_remediation_has_actionable_controls():
    rem = remediation_for("LLM01:2025")
    assert rem["controls"] and all(isinstance(c, str) for c in rem["controls"])


def test_unknown_owasp_returns_generic():
    rem = remediation_for("LLM99:2025")
    assert rem["title"] == "General Hardening"


def test_owasp_resolution_handles_chain_ids():
    # Multi-turn findings log ids like 'JB-003:CHAIN-001'.
    assert _owasp_for_technique_id("JB-003:CHAIN-001") == "LLM01:2025"


def test_findings_grouped_and_sorted_by_exposure():
    results = [
        {"technique_id": "PI-001", "success": True},   # LLM01
        {"technique_id": "PI-002", "success": True},   # LLM01
        {"technique_id": "DE-001", "success": True},   # LLM07
        {"technique_id": "DE-002", "success": False},  # ignored (blocked)
    ]
    report = remediations_for_findings(results)
    assert report[0]["owasp"] == "LLM01:2025"  # most findings first
    assert report[0]["finding_count"] == 2
    owasp_ids = {r["owasp"] for r in report}
    assert "LLM07:2025" in owasp_ids


def test_no_successes_yields_empty_report():
    assert remediations_for_findings([{"technique_id": "PI-001", "success": False}]) == []
