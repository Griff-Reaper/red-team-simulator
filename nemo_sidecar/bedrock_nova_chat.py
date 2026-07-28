# bedrock_nova_chat.py
"""
BedrockNovaChat — a minimal LangChain ``BaseChatModel`` over the Bedrock
``converse`` API, so NeMo Guardrails can drive the **same** Amazon Nova model the
main simulator's ``bedrock`` target uses.

Why this exists
---------------
NeMo Guardrails ships no Bedrock/Nova engine (built-ins are azure/openai/nim/
ollama; LangChain engines are anthropic/cohere/vertexai/…). To keep NeMo's base
model identical to the raw ``bedrock`` / ``bedrock-guardrails`` targets — so the
purple-team A/B compares three *defense postures over one base model* — we wrap
Nova in a LangChain chat model and register it as a custom NeMo provider
(see ``nemo_config/config.py``).

Runtime: this file is part of the **isolated Python 3.11 sidecar** and is never
imported by the main 3.14 app. It needs ``boto3`` + ``langchain-core`` and AWS
Bedrock credentials in the environment (same creds as the main ``bedrock`` target).
"""

from __future__ import annotations

import asyncio
import os
from functools import partial
from typing import Any, List, Optional

import boto3
from botocore.config import Config
from langchain_core.callbacks import (
    AsyncCallbackManagerForLLMRun,
    CallbackManagerForLLMRun,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult

# Read the same knobs the main app uses, so the sidecar's Nova is configured
# identically to the raw `bedrock` target.
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

# Module-level client cache. Kept off the pydantic model instance on purpose:
# BaseChatModel is a pydantic v2 model, and stashing a boto3 client as an instance
# attribute fights pydantic's field machinery. One client is safe to share.
_CLIENT: Any = None


def _client() -> Any:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = boto3.client(
            "bedrock-runtime",
            region_name=AWS_REGION,
            config=Config(retries={"max_attempts": MAX_RETRIES, "mode": "standard"}),
        )
    return _CLIENT


def _to_converse(messages: List[BaseMessage]):
    """Split LangChain messages into Bedrock ``converse`` (system blocks, turns).

    Bedrock keeps the system prompt in a separate ``system`` argument and requires
    strictly alternating user/assistant turns; NeMo's self-check flows only ever
    hand us a system block plus a single user turn, so a straightforward mapping
    is sufficient here.
    """
    system_blocks = []
    turns = []
    for m in messages:
        text = m.content if isinstance(m.content, str) else str(m.content)
        if isinstance(m, SystemMessage):
            system_blocks.append({"text": text})
        elif isinstance(m, AIMessage):
            turns.append({"role": "assistant", "content": [{"text": text}]})
        else:  # HumanMessage and any other role → user
            turns.append({"role": "user", "content": [{"text": text}]})
    return system_blocks, turns


class BedrockNovaChat(BaseChatModel):
    """LangChain chat model backed by Bedrock ``converse`` on Amazon Nova."""

    # NeMo passes the config.yml `model:` value in as `model`; default from env so
    # the sidecar still works if the config omits it.
    model: str = BEDROCK_MODEL_ID
    region_name: str = AWS_REGION
    temperature: float = 0.7
    max_tokens: int = 1024

    @property
    def _llm_type(self) -> str:
        return "bedrock_nova_chat"

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        system_blocks, turns = _to_converse(messages)
        request = {
            "modelId": self.model,
            "messages": turns,
            "inferenceConfig": {
                "temperature": self.temperature,
                "maxTokens": self.max_tokens,
            },
        }
        if system_blocks:
            request["system"] = system_blocks

        response = _client().converse(**request)
        text = response["output"]["message"]["content"][0]["text"]
        generation = ChatGeneration(message=AIMessage(content=text))
        return ChatResult(generations=[generation])

    async def _agenerate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        # boto3 is synchronous; NeMo's async path just needs a coroutine, so run the
        # blocking call in the default executor rather than blocking the loop.
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, partial(self._generate, messages, stop=stop, **kwargs)
        )
