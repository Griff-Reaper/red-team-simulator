# config.py
"""
Central configuration for the Red Team Simulator.

All secrets and tunables are sourced from the environment (via ``.env``) so the
same code runs unchanged across local dev, CI, and production. Model IDs are
centralized here — never hardcode them in the engines.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── Azure OpenAI (attack generator + target) ────────────────────────────────
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION")

# ── Anthropic (Claude target + judge) ───────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Model under test when the target is "claude". Override per engagement to test a
# specific model's safety posture. Must be a currently-served model ID.
CLAUDE_TARGET_MODEL = os.getenv("CLAUDE_TARGET_MODEL", "claude-sonnet-5")

# Model used to *judge* whether an attack succeeded. Use a strong, current model —
# judging quality gates the accuracy of every result in the system.
JUDGE_MODEL = os.getenv("JUDGE_MODEL", "claude-opus-4-8")

# ── Azure AI Search (optional — RAG-powered attack research) ─────────────────
AZURE_SEARCH_ENDPOINT = os.getenv("AZURE_SEARCH_ENDPOINT")
AZURE_SEARCH_KEY = os.getenv("AZURE_SEARCH_KEY")
AZURE_SEARCH_INDEX = os.getenv("AZURE_SEARCH_INDEX")

# ── Amazon Bedrock (optional target + Guardrails) ───────────────────────────
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")
BEDROCK_GUARDRAIL_ID = os.getenv("BEDROCK_GUARDRAIL_ID")
BEDROCK_GUARDRAIL_VERSION = os.getenv("BEDROCK_GUARDRAIL_VERSION", "DRAFT")
BEDROCK_GENERATOR_MODEL_ID = os.getenv("BEDROCK_GENERATOR_MODEL_ID", "us.meta.llama3-3-70b-instruct-v1:0")
# ── Simulator settings ──────────────────────────────────────────────────────
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "60"))  # per-request seconds
DEFAULT_TEMPERATURE = float(os.getenv("DEFAULT_TEMPERATURE", "0.9"))  # high creativity
RESULTS_DIR = os.getenv("RESULTS_DIR", "results")
# Result log is JSON Lines (one record per line): git-friendly and merge=union
# safe, so concurrent local + CI appends never conflict. LEGACY_LOG_FILE is read
# once for one-time migration from the old JSON-array format.
LOG_FILE = os.path.join(RESULTS_DIR, "attack_log.jsonl")
LEGACY_LOG_FILE = os.path.join(RESULTS_DIR, "attack_log.json")

# Bounded concurrency for batch testing. This IS the rate-limit control: at most
# MAX_WORKERS attacks are in flight at once, and the SDKs auto-retry 429s with
# backoff. Set to 1 for fully sequential (verbose, ordered) execution.
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))

# ── Config validation ───────────────────────────────────────────────────────
# Maps a capability to the env vars it requires, so we can fail fast with an
# actionable message instead of a cryptic SDK error deep in a run.
_REQUIRED_ENV = {
    "azure": [
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT",
        "AZURE_OPENAI_API_VERSION",
    ],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "bedrock": ["BEDROCK_MODEL_ID"],
    "bedrock-guardrails": ["BEDROCK_GUARDRAIL_ID"],
}


def missing_env(capability: str) -> list[str]:
    """Return the env vars required for ``capability`` that are unset/empty."""
    return [name for name in _REQUIRED_ENV.get(capability, []) if not os.getenv(name)]


def validate(capabilities: list[str], strict: bool = False) -> dict[str, list[str]]:
    """Validate that env vars for the given capabilities are present.

    Returns a mapping of capability -> missing vars (empty if all satisfied).
    With ``strict=True``, raises ``EnvironmentError`` if anything is missing.
    """
    problems = {cap: miss for cap in capabilities if (miss := missing_env(cap))}
    if strict and problems:
        lines = [f"  - {cap}: missing {', '.join(v)}" for cap, v in problems.items()]
        raise EnvironmentError(
            "Missing required configuration:\n" + "\n".join(lines)
            + "\n\nSet these in your .env file. See DEPLOYMENT_CHECKLIST.md."
        )
    return problems
