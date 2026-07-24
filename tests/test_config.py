"""Tests for config validation helpers."""

import config


def test_missing_env_reports_unset(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert "ANTHROPIC_API_KEY" in config.missing_env("anthropic")


def test_missing_env_satisfied(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert config.missing_env("anthropic") == []


def test_validate_returns_problem_map(monkeypatch):
    monkeypatch.delenv("BEDROCK_GUARDRAIL_ID", raising=False)
    problems = config.validate(["bedrock-guardrails"])
    assert "bedrock-guardrails" in problems


def test_validate_strict_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import pytest

    with pytest.raises(EnvironmentError):
        config.validate(["anthropic"], strict=True)


def test_unknown_capability_is_empty():
    assert config.missing_env("does-not-exist") == []
