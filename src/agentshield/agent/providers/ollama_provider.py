"""Ollama provider: a real, locally hosted open-weight model with structured tool calling.

- Talks to the Ollama HTTP API (`POST /api/chat`, non-streaming). Default endpoint is localhost, so
  prompts never leave the machine. No API key is involved.
- Requires a model that supports tool calling (e.g. `qwen2.5:7b`, `llama3.1:8b`).
- Timeouts and bounded retries on connection errors and 5xx responses.
- Cost is reported as 0.0 (local inference); token counts come from Ollama's eval counters.
- Results are labeled live (`is_simulated = False`): this is a real model, not the simulator.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from agentshield.agent.providers.base import (
    ChatMessage,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProposedToolCall,
    ProviderError,
    Usage,
)


def to_ollama_messages(system: str, messages: list[ChatMessage]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for m in messages:
        if m.role == "user":
            out.append({"role": "user", "content": m.content})
        elif m.role == "assistant":
            msg: dict[str, Any] = {"role": "assistant", "content": m.content}
            if m.tool_calls:
                msg["tool_calls"] = [{"function": {"name": tc.name, "arguments": tc.arguments}} for tc in m.tool_calls]
            out.append(msg)
        else:
            out.append({"role": "tool", "content": m.content, "tool_name": m.tool_name or ""})
    return out


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"_unparsed": raw[:2000]}
        return parsed if isinstance(parsed, dict) else {"_unparsed": raw[:2000]}
    return {}


class OllamaProvider(ModelProvider):
    name = "ollama"
    is_simulated = False

    def __init__(
        self,
        model: str = "qwen2.5:7b",
        *,
        base_url: str = "http://127.0.0.1:11434",
        timeout: float = 120.0,
        max_retries: int = 2,
        temperature: float | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ProviderError(f"invalid Ollama base URL: {base_url!r}")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self.temperature = temperature
        self.client = client or httpx.Client(timeout=timeout)

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.client.post(f"{self.base_url}/api/chat", json=payload)
            except httpx.TimeoutException as exc:
                last = ProviderError("request to Ollama timed out")
                last.__cause__ = exc
            except httpx.TransportError as exc:
                last = ProviderError(f"cannot reach Ollama at {self.base_url} (is `ollama serve` running?)")
                last.__cause__ = exc
            else:
                if resp.status_code == 404:
                    raise ProviderError(f"model '{self.model}' not found in Ollama: run `ollama pull {self.model}`")
                if resp.status_code == 400:
                    raise ProviderError(f"Ollama rejected the request: {resp.text[:300]}")
                if resp.status_code >= 500:
                    last = ProviderError(f"Ollama server error HTTP {resp.status_code}: {resp.text[:200]}")
                else:
                    resp.raise_for_status()
                    data: dict[str, Any] = resp.json()
                    return data
            if attempt < self.max_retries:
                time.sleep(min(2.0 * (attempt + 1), 5.0))
        assert last is not None
        raise last

    def complete(self, request: ModelRequest) -> ModelResponse:
        options: dict[str, Any] = {"num_predict": request.max_output_tokens}
        if self.temperature is not None:
            options["temperature"] = self.temperature
        payload = {
            "model": self.model,
            "stream": False,
            "messages": to_ollama_messages(request.system, request.messages),
            "tools": [
                {
                    "type": "function",
                    "function": {"name": t.name, "description": t.description, "parameters": t.input_schema},
                }
                for t in request.tools
            ],
            "options": options,
        }
        started = time.perf_counter()
        data = self._post(payload)
        latency = (time.perf_counter() - started) * 1000

        message = data.get("message") or {}
        turn = sum(1 for m in request.messages if m.role == "assistant")
        calls = [
            ProposedToolCall(
                id=str(tc.get("id") or f"ollama_{turn}_{i}"),
                name=str((tc.get("function") or {}).get("name", "")),
                arguments=_parse_arguments((tc.get("function") or {}).get("arguments")),
            )
            for i, tc in enumerate(message.get("tool_calls") or [])
        ]
        return ModelResponse(
            text=(message.get("content") or "").strip(),
            tool_calls=calls,
            stop_reason="tool_use" if calls else (data.get("done_reason") or "stop"),
            model=data.get("model") or self.model,
            latency_ms=round(latency, 2),
            usage=Usage(
                input_tokens=int(data.get("prompt_eval_count") or 0),
                output_tokens=int(data.get("eval_count") or 0),
                estimated=False,
                cost_usd=0.0,
            ),
            raw={"done_reason": data.get("done_reason"), "total_duration_ns": data.get("total_duration")},
        )
