"""Provider-neutral model request/response types and the adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, Field

Trust = Literal["trusted", "principal", "untrusted", "model"]


class ProposedToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any]


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "tool"]
    trust: Trust
    content: str = ""
    tool_calls: list[ProposedToolCall] = Field(default_factory=list)
    tool_call_id: str | None = None
    tool_name: str | None = None
    is_error: bool = False
    # Original provider content blocks for assistant turns (e.g. thinking blocks) that must be replayed verbatim.
    provider_content: list[dict[str, Any]] | None = None


class ToolDefinition(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]


class ModelRequest(BaseModel):
    system: str
    messages: list[ChatMessage]
    tools: list[ToolDefinition]
    max_output_tokens: int = 1024


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    estimated: bool = False
    cost_usd: float | None = None


class ModelResponse(BaseModel):
    text: str = ""
    tool_calls: list[ProposedToolCall] = Field(default_factory=list)
    stop_reason: str = "end_turn"
    usage: Usage = Field(default_factory=Usage)
    model: str
    latency_ms: float = 0.0
    raw: dict[str, Any] = Field(default_factory=dict)


class ProviderError(RuntimeError):
    pass


class ModelProvider(ABC):
    name: str
    model: str
    is_simulated: bool

    @abstractmethod
    def complete(self, request: ModelRequest) -> ModelResponse: ...
