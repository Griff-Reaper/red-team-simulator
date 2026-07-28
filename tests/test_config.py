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


def test_bedrock_nemo_capability_registered():
    # The NeMo-guarded target reuses the base Bedrock model id (rails run in the
    # sidecar). The sidecar URL has a working default, so it isn't a hard requirement.
    assert "bedrock-nemo" in config._REQUIRED_ENV
    assert "BEDROCK_MODEL_ID" in config._REQUIRED_ENV["bedrock-nemo"]
    assert config.NEMO_SIDECAR_URL  # a usable default is always present


def test_target_ids_stay_in_sync():
    """A new target must be added to every registry at once, not just one.

    The interactive menu and SUPPORTED_TARGETS must match exactly, and every
    supported bedrock variant must have a dashboard config + css-class mapping.
    """
    from target_tester import TargetTester
    import main
    import generate_dashboard as gd

    supported = set(TargetTester.SUPPORTED_TARGETS)
    menu = set(main._TARGET_MENU.values())
    assert menu == supported, f"menu {menu} drifted from SUPPORTED_TARGETS {supported}"

    # bedrock-nemo specifically is wired end-to-end.
    assert "bedrock-nemo" in supported
    assert "bedrock-nemo" in gd.TARGET_CONFIG
    assert gd._target_css_class("bedrock-nemo") == "bedrock-nemo"
    # The 'nemo' branch must win over the bare 'bedrock' substring.
    assert gd._target_css_class("bedrock") == "bedrock"
    assert gd._target_css_class("bedrock-guardrails") == "bedrock-guardrails"
