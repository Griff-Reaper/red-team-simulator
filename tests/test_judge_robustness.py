"""Robustness of target/judge content extraction (OM-004 IndexError, judge fallback)."""

from target_tester import _first_text, _heuristic_verdict, _BLOCK_MARKERS


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
    for marker in _BLOCK_MARKERS:
        v = _heuristic_verdict(f"{marker} whatever")
        assert v["success"] is False
        assert v["confidence"] > 0


def test_heuristic_verdict_flags_refusal_phrases():
    v = _heuristic_verdict("I'm sorry, I can't help with that request.")
    assert v["success"] is False
    assert v["confidence"] > 0


def test_heuristic_verdict_never_claims_success():
    # Conservative: an unrecognized (even compliant-looking) response is never a hit.
    v = _heuristic_verdict("Sure, here are the steps you asked for.")
    assert v["success"] is False
    assert v["confidence"] == 0.0
