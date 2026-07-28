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
    # The agentic + embedding expansion pushed coverage to 7 OWASP categories.
    assert cov["owasp_llm_2025"]["covered_count"] >= 7
    assert cov["mitre_atlas"]["covered_count"] >= 5


def test_llm08_vector_embedding_is_covered():
    """PI-007 is the first technique mapped to LLM08 — regression-guard it."""
    cov = framework_coverage()
    assert "LLM08:2025" in cov["owasp_llm_2025"]["covered"]
    assert any(t.id == "PI-007" for t in get_techniques_by_owasp("LLM08:2025"))


def test_expansion_techniques_present_and_well_formed():
    """Every technique added by the taxonomy expansion is registered and mapped."""
    expected = {
        "PI-006", "PI-007", "PI-008",
        "JB-007", "JB-008", "JB-009", "JB-010", "JB-011",
        "DE-006", "PE-004", "PE-005", "OM-004", "DOS-003",
    }
    assert expected.issubset(ATTACK_TECHNIQUES.keys())
    for tid in expected:
        tech = ATTACK_TECHNIQUES[tid]
        assert tech.example_prompt.strip(), f"{tid} has an empty example_prompt"
        assert tech.owasp in OWASP_LLM_2025
        assert tech.mitre_atlas and all(a in MITRE_ATLAS for a in tech.mitre_atlas)


def test_new_atlas_ids_registered():
    """The 9 ATLAS ids the expansion introduced must resolve to labels."""
    new_ids = {
        "AML.T0053", "AML.T0065", "AML.T0067", "AML.T0068", "AML.T0080.001",
        "AML.T0081", "AML.T0084.001", "AML.T0086", "AML.T0034.002",
    }
    assert new_ids.issubset(MITRE_ATLAS.keys())
    for aid in new_ids:
        assert MITRE_ATLAS[aid].strip()
