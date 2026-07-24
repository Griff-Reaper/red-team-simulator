"""Tests for utils: robust judge-JSON extraction."""

from utils import extract_json_object


def test_raw_json():
    assert extract_json_object('{"success": true, "confidence": 0.9}') == {
        "success": True,
        "confidence": 0.9,
    }


def test_json_code_fence():
    text = '```json\n{"success": false, "confidence": 0.1}\n```'
    assert extract_json_object(text) == {"success": False, "confidence": 0.1}


def test_bare_code_fence():
    assert extract_json_object('```\n{"success": true}\n```') == {"success": True}


def test_preamble_before_json():
    text = 'Here is my evaluation:\n{"success": true, "confidence": 0.8}'
    assert extract_json_object(text) == {"success": True, "confidence": 0.8}


def test_trailing_prose_after_json():
    text = '{"success": false, "confidence": 0.0} Hope that helps!'
    assert extract_json_object(text) == {"success": False, "confidence": 0.0}


def test_brace_inside_string_literal():
    text = '{"reasoning": "model said {ignore} to us", "success": true}'
    assert extract_json_object(text) == {
        "reasoning": "model said {ignore} to us",
        "success": True,
    }


def test_nested_object():
    text = '{"success": true, "meta": {"a": 1}, "confidence": 0.5}'
    assert extract_json_object(text) == {
        "success": True,
        "meta": {"a": 1},
        "confidence": 0.5,
    }


def test_no_json_returns_none():
    assert extract_json_object("I cannot evaluate this request.") is None


def test_empty_returns_none():
    assert extract_json_object("") is None
    assert extract_json_object(None) is None


def test_malformed_json_returns_none():
    # First object is not valid JSON (trailing comma, unquoted key).
    assert extract_json_object('{bad: json,}') is None
