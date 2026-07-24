"""Tests for the verification engine (deterministic aggregation + panel logic)."""

from verification import aggregate_votes, FindingVerifier


def test_aggregate_majority_confirms():
    votes = [{"refuted": False}, {"refuted": False}, {"refuted": True}]
    v = aggregate_votes(votes)
    assert v["verified"] is True
    assert v["confirmed"] == 2
    assert v["votes"] == 3


def test_aggregate_majority_refutes():
    votes = [{"refuted": True}, {"refuted": True}, {"refuted": False}]
    assert aggregate_votes(votes)["verified"] is False


def test_aggregate_empty_is_unverified():
    assert aggregate_votes([])["verified"] is False


def test_missing_refuted_defaults_to_refuted():
    # A malformed vote (no 'refuted') is treated conservatively as a refutation.
    assert aggregate_votes([{}, {}])["confirmed"] == 0


def test_verify_finding_with_injected_panel():
    # Injected judge always confirms (refuted=False) → verified.
    verifier = FindingVerifier(judge_fn=lambda a, r, lens: {"refuted": False}, num_judges=3)
    verdict = verifier.verify_finding({"technique_id": "PI-001"}, "sure, here you go")
    assert verdict["verified"] is True
    assert verdict["votes"] == 3


def test_verify_results_downgrades_false_positives():
    # Judge always refutes → every claimed success is downgraded.
    verifier = FindingVerifier(judge_fn=lambda a, r, lens: {"refuted": True}, num_judges=3)
    results = [
        {"technique_id": "PI-001", "target": "claude", "success": True, "response": "no"},
        {"technique_id": "DE-001", "target": "claude", "success": False, "response": "no"},
    ]
    report = verifier.verify_results(results)
    assert report["summary"]["claimed_successes"] == 1
    assert report["summary"]["downgraded"] == 1
    assert report["summary"]["confirmed"] == 0


def test_threshold_skips_low_severity_without_verifying():
    calls = {"n": 0}

    def counting_judge(a, r, lens):
        calls["n"] += 1
        return {"refuted": True}  # would downgrade if actually run

    verifier = FindingVerifier(judge_fn=counting_judge, num_judges=3)
    results = [
        {"technique_id": "DOS-002", "target": "c", "success": True, "severity": "low", "response": "x"},
        {"technique_id": "DE-001", "target": "c", "success": True, "severity": "critical", "response": "x"},
    ]
    report = verifier.verify_results(results, min_severity="high")

    # Low-severity finding trusted without spending verifier calls; only the
    # critical one is actually judged (3 votes).
    assert report["summary"]["skipped_below_threshold"] == 1
    assert calls["n"] == 3
    # The critical finding was refuted → downgraded; the low one stays confirmed.
    assert report["summary"]["confirmed"] == 1
    assert report["summary"]["downgraded"] == 1


def test_verifier_survives_a_throwing_judge():
    def flaky(a, r, lens):
        raise RuntimeError("judge crashed")
    verifier = FindingVerifier(judge_fn=flaky, num_judges=2)
    verdict = verifier.verify_finding({"technique_id": "PI-001"}, "x")
    # Errors count as refutations → not verified, but no exception escapes.
    assert verdict["verified"] is False
