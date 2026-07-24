# clients.py
"""
Centralized SDK client factory.

Single source of truth for how the simulator talks to model providers. Every
client is constructed with consistent retry and timeout policy (honoring
``MAX_RETRIES`` / ``REQUEST_TIMEOUT`` from config), so behaviour is uniform and
tunable from one place instead of duplicated across every engine.

Both the Anthropic and OpenAI SDKs auto-retry transient failures (429s and 5xx)
with exponential backoff up to ``max_retries`` — bounding blast radius on rate
limits without any hand-rolled retry loops.
"""

from anthropic import Anthropic
from openai import AzureOpenAI

from config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_API_VERSION,
    ANTHROPIC_API_KEY,
    AWS_REGION,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
)


def anthropic_client() -> Anthropic:
    """Anthropic client for Claude targets and the LLM judge."""
    return Anthropic(
        api_key=ANTHROPIC_API_KEY,
        max_retries=MAX_RETRIES,
        timeout=REQUEST_TIMEOUT,
    )


def azure_openai_client() -> AzureOpenAI:
    """Azure OpenAI client for the attack generator and the GPT target."""
    return AzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_version=AZURE_OPENAI_API_VERSION,
        max_retries=MAX_RETRIES,
        timeout=REQUEST_TIMEOUT,
    )


def azure_deployment() -> str:
    """The configured Azure OpenAI deployment name (model)."""
    return AZURE_OPENAI_DEPLOYMENT


def bedrock_client():
    """Amazon Bedrock runtime client. Imports boto3 lazily (optional dependency)."""
    try:
        import boto3
        from botocore.config import Config
    except ImportError as e:
        raise RuntimeError(
            "Bedrock target requires boto3. Install it with: pip install boto3"
        ) from e
    return boto3.client(
        "bedrock-runtime",
        region_name=AWS_REGION,
        config=Config(retries={"max_attempts": MAX_RETRIES, "mode": "standard"}),
    )
