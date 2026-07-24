"""Tests for automated_run mode execution — variations propagation."""

import automated_run


class _FakeGen:
    """Records the count_per_technique it was called with; 15 techniques."""
    N_TECHNIQUES = 15

    def __init__(self):
        self.count = None

    def generate_batch(self, technique_ids=None, count_per_technique=1, temperature=None):
        self.count = count_per_technique
        return [
            {"technique_id": f"T{i}", "technique_name": "n", "category": "c",
             "severity": "low", "generated_prompt": "p"}
            for i in range(self.N_TECHNIQUES * count_per_technique)
        ]


class _FakeTester:
    def test_batch(self, attacks, targets):
        return [
            {"technique_id": a["technique_id"], "target": t, "success": False}
            for a in attacks for t in targets
        ]


def test_full_mode_passes_variations_to_generator():
    gen, tester = _FakeGen(), _FakeTester()
    automated_run.run_full_assault(gen, tester, ["a", "b", "c"], variations=4)
    assert gen.count == 4  # not silently defaulted to 1


def test_full_mode_variations_scale_total_attacks():
    gen, tester = _FakeGen(), _FakeTester()
    one = automated_run.run_full_assault(gen, tester, ["a", "b", "c"], variations=1)
    two = automated_run.run_full_assault(gen, tester, ["a", "b", "c"], variations=2)
    # 15 techniques × 3 targets × N variations.
    assert len(one) == 15 * 3 * 1
    assert len(two) == 15 * 3 * 2
    assert len(two) == 2 * len(one)


def test_full_mode_defaults_to_one_variation():
    gen, tester = _FakeGen(), _FakeTester()
    automated_run.run_full_assault(gen, tester, ["a"])
    assert gen.count == 1
