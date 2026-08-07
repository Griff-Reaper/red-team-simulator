"""Robustness of target/judge content extraction (OM-004 IndexError, judge fallback)."""

from target_tester import _first_text, _heuristic_verdict, _sentinel_verdict
from utils import DEFENSE_BLOCK_MARKERS, ERROR_MARKERS, OUTCOME_BLOCKED, OUTCOME_ERROR


class _Block:
    """Stand-in for an Anthropic content block; omit text to model an empty block."""
    def __init__(self, text=None):
        if text is not None:
            self.text = text


def test_first_text_tolerates_empty_content():
    # An empty content list is exactly the refusal case that used to crash on [0].
    assert _first_text([]) == ""
    assert _first_text(None) == ""


def test_first_text_skips_blocks_without_text():
    assert _first_text([_Block()]) == ""


def test_first_text_returns_first_text_block():
    assert _first_text([_Block("hello"), _Block("world")]) == "hello"


def test_heuristic_verdict_flags_block_markers():
    for marker in DEFENSE_BLOCK_MARKERS:
        v = _heuristic_verdict(f"{marker} whatever")
        assert v["success"] is False
        assert v["confidence"] > 0
        assert v["outcome"] == OUTCOME_BLOCKED


def test_heuristic_verdict_marks_error_markers_inconclusive():
    # An errored/empty response reaching the heuristic is inconclusive, never a block.
    for marker in ERROR_MARKERS:
        v = _heuristic_verdict(f"{marker} whatever")
        assert v["success"] is False
        assert v["outcome"] == OUTCOME_ERROR


def test_heuristic_verdict_flags_refusal_phrases():
    v = _heuristic_verdict("I'm sorry, I can't help with that request.")
    assert v["success"] is False
    assert v["confidence"] > 0


def test_heuristic_verdict_never_claims_success():
    # Conservative: an unrecognized (even compliant-looking) response is never a hit.
    v = _heuristic_verdict("Sure, here are the steps you asked for.")
    assert v["success"] is False
    assert v["confidence"] == 0.0


# ── deterministic sentinel routing (skips the LLM judge) ────────────────────

def test_sentinel_verdict_resolves_defense_blocks_deterministically():
    for marker in DEFENSE_BLOCK_MARKERS:
        v = _sentinel_verdict(f"{marker} blocked by policy")
        assert v is not None
        assert v["success"] is False
        assert v["outcome"] == OUTCOME_BLOCKED
        assert v["confidence"] >= 0.99  # certain, not the noisy 0.6 heuristic


def test_sentinel_verdict_marks_errors_inconclusive_not_blocked():
    for marker in ERROR_MARKERS:
        v = _sentinel_verdict(f"{marker} the target fell over")
        assert v is not None
        assert v["outcome"] == OUTCOME_ERROR  # never counted as a defensive win


def test_sentinel_verdict_defers_genuine_responses_to_the_judge():
    # Real model output has no sentinel prefix — the judge must still run.
    assert _sentinel_verdict("Sure, here is the answer you wanted.") is None
    assert _sentinel_verdict("I can't help with that.") is None
