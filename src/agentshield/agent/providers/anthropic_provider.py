"""Anthropic Messages API provider with structured tool calling.

- Credentials are resolved by the SDK (ANTHROPIC_API_KEY or an `ant auth login` profile); never stored.
- Timeouts and bounded retries are configured on the client.
- Untrusted tool output is returned as `tool_result` blocks, already wrapped in labeled delimiters by
  the runtime; the system prompt tells the model to treat it as data.
- Assistant turns are replayed with their original content blocks (including thinking blocks), as the
  API requires.
- Server-side refusal fallbacks (`fallbacks: "default"`) are on by default. When a fallback model
  serves a turn, the response records it, so evidence never attributes that turn to the requested model.
"""

from __future__ import annotations

import time
from typing import Any

from agentshield.agent.providers.base import (
    ChatMessage,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProposedToolCall,
    ProviderError,
    Usage,
)

# USD per million tokens (input, output). Used only for cost *estimates*; cache pricing is ignored.
PRICING: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (10.0, 50.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
}

FALLBACK_BETA = "server-side-fallback-2026-07-01"
_REPLAY_DROP = {"fallback"}  # audit marker; safe to drop when echoing


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float | None:
    price = PRICING.get(model)
    if price is None:
        return None
    return round(input_tokens / 1e6 * price[0] + output_tokens / 1e6 * price[1], 6)


def to_api_messages(messages: list[ChatMessage]) -> list[dict[str, Any]]:
    """Map provider-neutral messages to Messages API turns.

    Consecutive tool results are grouped into a single user message, as the API expects for
    parallel tool calls.
    """
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "user":
            out.append({"role": "user", "content": m.content})
        elif m.role == "assistant":
            if m.provider_content is not None:
                content = [b for b in m.provider_content if b.get("type") not in _REPLAY_DROP]
            else:
                content = ([{"type": "text", "text": m.content}] if m.content else []) + [
                    {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments} for tc in m.tool_calls
                ]
            out.append({"role": "assistant", "content": content})
        else:
            block = {
                "type": "tool_result",
                "tool_use_id": m.tool_call_id,
                "content": m.content,
                "is_error": m.is_error,
            }
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return out


class AnthropicProvider(ModelProvider):
    name = "anthropic"
    is_simulated = False

    def __init__(
        self,
        model: str = "claude-opus-5-5",
        *,
        effort: str = "medium",
        timeout: float = 60.0,
        max_retries: int = 2,
        refusal_fallback: bool = True,
        client: Any = None,
    ) -> None:
        self.model = model
        self.effort = effort
        self.refusal_fallback = refusal_fallback
        if client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - depends on optional extra
                raise ProviderError("anthropic SDK not installed: pip install 'agentshield[anthropic]'") from exc
            client = anthropic.Anthropic(timeout=timeout, max_retries=max_retries)
        self.client = client

    def complete(self, request: ModelRequest) -> ModelResponse:
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": request.max_output_tokens,
            "system": request.system,
            "messages": to_api_messages(request.messages),
            "tools": [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in request.tools
            ],
            "output_config": {"effort": self.effort},
        }
        if self.refusal_fallback:
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
        started = time.perf_counter()
        try:
            resp = self.client.beta.messages.create(**params)
        except Exception as exc:
            raise ProviderError(_describe_error(exc)) from exc
        latency = (time.perf_counter() - started) * 1000

        data: dict[str, Any] = resp.to_dict()
        content: list[dict[str, Any]] = data.get("content", [])
        usage = data.get("usage") or {}
        served_by = data.get("model", self.model)
        fallback_ran = any(it.get("type") == "fallback_message" for it in usage.get("iterations") or [])
        in_tok = int(usage.get("input_tokens") or 0)
        out_tok = int(usage.get("output_tokens") or 0)
        stop = data.get("stop_reason") or "end_turn"

        text = ""
        calls: list[ProposedToolCall] = []
        if stop != "refusal":
            text = "\n".join(b.get("text", "") for b in content if b.get("type") == "text").strip()
            calls = [
                ProposedToolCall(id=b["id"], name=b["name"], arguments=b.get("input") or {})
                for b in content
                if b.get("type") == "tool_use"
            ]
        return ModelResponse(
            text=text,
            tool_calls=calls,
            stop_reason=stop,
            model=served_by,
            latency_ms=round(latency, 2),
            usage=Usage(
                input_tokens=in_tok,
                output_tokens=out_tok,
                estimated=False,
                cost_usd=estimate_cost(served_by, in_tok, out_tok),
            ),
            raw={
                "content": content,
                "id": data.get("id"),
                "requested_model": self.model,
                "fallback_ran": fallback_ran,
                "stop_details": data.get("stop_details"),
            },
        )


def _describe_error(exc: Exception) -> str:
    """Map SDK errors to safe messages (no credentials, no request bodies)."""
    try:
        import anthropic
    except ImportError:  # pragma: no cover
        return f"{type(exc).__name__}"
    if isinstance(exc, anthropic.AuthenticationError):
        return "authentication failed: check ANTHROPIC_API_KEY or `ant auth login`"
    if isinstance(exc, anthropic.PermissionDeniedError):
        return "permission denied for this model or feature"
    if isinstance(exc, anthropic.NotFoundError):
        return "model or endpoint not found"
    if isinstance(exc, anthropic.RateLimitError):
        return "rate limited after bounded retries"
    if isinstance(exc, anthropic.APITimeoutError):
        return "request timed out after bounded retries"
    if isinstance(exc, anthropic.APIConnectionError):
        return "network error contacting the provider"
    if isinstance(exc, anthropic.BadRequestError):
        return f"bad request: {getattr(exc, 'message', '')[:300]}"
    if isinstance(exc, anthropic.APIStatusError):
        return f"provider error HTTP {exc.status_code}"
    return f"{type(exc).__name__}: {str(exc)[:200]}"
