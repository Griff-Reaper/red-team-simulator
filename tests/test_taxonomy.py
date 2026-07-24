"""Tests for the attack taxonomy and framework mappings."""

from attack_taxonomy import (
    ATTACK_TECHNIQUES,
    OWASP_LLM_2025,
    MITRE_ATLAS,
    framework_coverage,
    get_techniques_by_owasp,
    get_techniques_by_atlas,
)


def test_every_technique_has_framework_mappings():
    """Enterprise credibility: no technique may be unmapped."""
    for tid, tech in ATTACK_TECHNIQUES.items():
        assert tech.owasp, f"{tid} missing OWASP mapping"
        assert tech.mitre_atlas, f"{tid} missing MITRE ATLAS mapping"


def test_owasp_ids_are_valid():
    for tech in ATTACK_TECHNIQUES.values():
        assert tech.owasp in OWASP_LLM_2025, f"unknown OWASP id: {tech.owasp}"


def test_atlas_ids_are_valid():
    for tech in ATTACK_TECHNIQUES.values():
        for atlas_id in tech.mitre_atlas:
            assert atlas_id in MITRE_ATLAS, f"unknown ATLAS id: {atlas_id}"


def test_technique_ids_are_self_consistent():
    for tid, tech in ATTACK_TECHNIQUES.items():
        assert tech.id == tid


def test_lookup_by_owasp():
    techniques = get_techniques_by_owasp("LLM01:2025")
    ids = {t.id for t in techniques}
    assert {"PI-001", "JB-001"}.issubset(ids)


def test_lookup_by_atlas():
    jailbreaks = get_techniques_by_atlas("AML.T0054")
    assert {"JB-001", "JB-002", "JB-003"}.issubset({t.id for t in jailbreaks})


def test_framework_coverage_shape():
    cov = framework_coverage()
    assert cov["techniques"] == len(ATTACK_TECHNIQUES)
    assert cov["owasp_llm_2025"]["total"] == 10
    assert cov["owasp_llm_2025"]["covered_count"] >= 5
    assert cov["mitre_atlas"]["covered_count"] >= 5
