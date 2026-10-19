"""Ollama adapter tests against a mocked HTTP transport. No Ollama server or model is needed."""

import json
from typing import Any

import httpx
import pytest

from agentshield.agent.providers.base import ChatMessage, ModelRequest, ProposedToolCall, ProviderError, ToolDefinition
from agentshield.agent.providers.ollama_provider import OllamaProvider, to_ollama_messages
from agentshield.redteam.engine import run_scenario
from agentshield.redteam.scenarios import SCENARIOS


def mock_client(responses: list[Any], seen: list[dict[str, Any]]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        r = responses.pop(0)
        if isinstance(r, Exception):
            raise r
        status, body = r
        return httpx.Response(status, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def chat(content: str = "", tool_calls: list | None = None, **extra: Any) -> tuple[int, dict]:
    msg: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        msg["tool_calls"] = tool_calls
    return 200, {
        "model": "qwen2.5:7b",
        "message": msg,
        "done_reason": "stop",
        "prompt_eval_count": 120,
        "eval_count": 30,
        **extra,
    }


def request() -> ModelRequest:
    return ModelRequest(
        system="sys",
        messages=[ChatMessage(role="user", trust="principal", content="hi")],
        tools=[ToolDefinition(name="search_documents", description="d", input_schema={"type": "object"})],
        max_output_tokens=256,
    )


def test_message_mapping_keeps_channels_separate():
    msgs = [
        ChatMessage(role="user", trust="principal", content="q"),
        ChatMessage(
            role="assistant",
            trust="model",
            tool_calls=[ProposedToolCall(id="a", name="search_documents", arguments={"query": "x"})],
        ),
        ChatMessage(
            role="tool",
            trust="untrusted",
            content="<untrusted_tool_output>r</untrusted_tool_output>",
            tool_call_id="a",
            tool_name="search_documents",
        ),
    ]
    out = to_ollama_messages("sys", msgs)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool"]
    assert out[2]["tool_calls"][0]["function"] == {"name": "search_documents", "arguments": {"query": "x"}}
    assert out[3]["tool_name"] == "search_documents"


def test_request_payload_and_response_parsing():
    seen: list[dict] = []
    client = mock_client(
        [chat(tool_calls=[{"function": {"name": "search_documents", "arguments": {"query": "q3"}}}])], seen
    )
    r = OllamaProvider(client=client, temperature=0.2).complete(request())
    body = seen[0]
    assert body["model"] == "qwen2.5:7b" and body["stream"] is False
    assert body["tools"][0]["type"] == "function" and body["tools"][0]["function"]["name"] == "search_documents"
    assert body["options"] == {"num_predict": 256, "temperature": 0.2}
    assert r.tool_calls[0].name == "search_documents" and r.tool_calls[0].arguments == {"query": "q3"}
    assert r.tool_calls[0].id == "ollama_0_0" and r.stop_reason == "tool_use"
    assert r.usage.input_tokens == 120 and r.usage.output_tokens == 30 and r.usage.cost_usd == 0.0


def test_string_and_malformed_arguments():
    seen: list[dict] = []
    client = mock_client(
        [
            chat(
                tool_calls=[
                    {"function": {"name": "a", "arguments": '{"query": "x"}'}},
                    {"function": {"name": "b", "arguments": "not json"}},
                ]
            )
        ],
        seen,
    )
    calls = OllamaProvider(client=client).complete(request()).tool_calls
    assert calls[0].arguments == {"query": "x"}
    assert calls[1].arguments == {"_unparsed": "not json"}  # the gateway's schema check will reject this


def test_missing_model_gives_pull_hint():
    client = mock_client([(404, {"error": "model not found"})], [])
    with pytest.raises(ProviderError, match="ollama pull"):
        OllamaProvider(client=client, max_retries=0).complete(request())


def test_connection_errors_are_retried_then_reported(monkeypatch):
    monkeypatch.setattr("agentshield.agent.providers.ollama_provider.time.sleep", lambda s: None)
    err = httpx.ConnectError("refused")
    client = mock_client([err, err, chat("ok")], [])
    assert OllamaProvider(client=client, max_retries=2).complete(request()).text == "ok"
    client = mock_client([err, err], [])
    with pytest.raises(ProviderError, match="cannot reach Ollama"):
        OllamaProvider(client=client, max_retries=1).complete(request())


def test_invalid_base_url_rejected():
    with pytest.raises(ProviderError):
        OllamaProvider(base_url="file:///etc/passwd")


def test_live_label_and_evaluation_through_runtime():
    client = mock_client([chat("Here is a summary of the onboarding guide.")], [])
    r = run_scenario(SCENARIOS["direct-injection"], OllamaProvider(client=client), "protected")
    assert r.trace.is_simulated is False and r.trace.provider == "ollama"
    assert r.evaluation["outcome"] == "failed" and r.evaluation["defense_layer"] == "model"
    assert r.trace.usage["cost_usd"] == 0.0


def test_unreachable_server_marks_run_errored(monkeypatch):
    monkeypatch.setattr("agentshield.agent.providers.ollama_provider.time.sleep", lambda s: None)
    client = mock_client([httpx.ConnectError("refused")], [])
    r = run_scenario(SCENARIOS["direct-injection"], OllamaProvider(client=client, max_retries=0), "protected")
    assert r.evaluation["outcome"] == "errored" and "cannot reach Ollama" in r.trace.error


def test_registry_builds_ollama_from_settings(monkeypatch):
    from agentshield.agent.providers import get_provider
    from agentshield.config import get_settings

    monkeypatch.setenv("AGENTSHIELD_OLLAMA_MODEL", "llama3.1:8b")
    get_settings.cache_clear()
    try:
        p = get_provider("ollama")
        assert p.name == "ollama" and p.model == "llama3.1:8b" and not p.is_simulated
    finally:
        get_settings.cache_clear()
