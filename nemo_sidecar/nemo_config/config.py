# config.py (inside the NeMo config dir)
"""
NeMo Guardrails auto-imports this module when it loads the config directory. Its
job: register the custom ``bedrock_nova_chat`` provider so the ``engine:
bedrock_nova_chat`` reference in ``config.yml`` resolves to :class:`BedrockNovaChat`.

Run the sidecar with ``NEMOGUARDRAILS_LLM_FRAMEWORK=langchain`` so NeMo treats the
provider as a LangChain chat model.
"""

import os
import sys

# The adapter lives one level up (the sidecar root), which isn't on sys.path when
# NeMo imports this config module — add it so the import resolves.
_SIDECAR_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SIDECAR_ROOT not in sys.path:
    sys.path.insert(0, _SIDECAR_ROOT)

from bedrock_nova_chat import BedrockNovaChat  # noqa: E402


def _register() -> None:
    """Register BedrockNovaChat as a NeMo chat provider.

    The registration entry point moved across NeMo versions; try the chat-provider
    API first (current), then fall back to the generic LLM-provider API. Pin the
    NeMo version in requirements.txt and confirm which one your install exposes.
    """
    try:
        from nemoguardrails.llm.providers import register_chat_provider
        register_chat_provider("bedrock_nova_chat", BedrockNovaChat)
        return
    except Exception:
        pass

    from nemoguardrails.llm.providers import register_llm_provider
    register_llm_provider("bedrock_nova_chat", BedrockNovaChat)


_register()
