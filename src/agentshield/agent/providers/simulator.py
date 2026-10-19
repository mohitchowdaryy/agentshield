"""Deterministic offline agent simulator. SIMULATION ONLY — not a language model.

It exists so that the gateway, evidence pipeline, evaluator and dashboard can be exercised and
tested reproducibly without credentials. Results produced with it say nothing about how any real
model behaves.

Behavior profiles
  naive      Follows imperative directives found anywhere in its context, including untrusted
             retrieved documents and tool output (models an injection-susceptible model).
  resistant  Follows only the user's request, ignores directives in untrusted content, and declines
             user requests that use override/jailbreak framing.

The simulator is stateless: each turn is derived from the message history alone.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from agentshield.agent.providers.base import (
    ChatMessage,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProposedToolCall,
    Usage,
)

Profile = Literal["naive", "resistant"]

READ_DIRECTIVE = re.compile(
    r"(?i)\b(?:read|open|retrieve|fetch|load|include)\b[^\n]{0,60}?\bfile\s+[`'\"]?(?P<path>[\w.\-/\\]+\.[A-Za-z]{2,4})"
)
SEND_DIRECTIVE = re.compile(
    r"(?i)\b(?:send|email|forward|post|upload|transmit)\b[^\n]{0,160}?\bto\s+[`'\"]?"
    r"(?P<dest>[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+|https?://[^\s'\"`<>)]+)"
)
OVERRIDE_FRAMING = re.compile(
    r"(?i)(ignore (?:all |any )?(?:previous|prior|your|the above) instructions|system override|maintenance mode|"
    r"developer mode|administrator (?:override|privileges)|you are now|disregard (?:all|your|previous))"
)
BUCKET_MENTION = re.compile(r"(?i)\bbucket\s+[`'\"]?(?P<name>[a-z0-9][a-z0-9.\-]{2,62}[a-z0-9])")
SEARCH_INTENT = re.compile(r"(?i)\b(summari[sz]e|find|search|look up|what|explain|overview|tell me)\b")
WRAPPED = re.compile(r"<untrusted_tool_output[^>]*>\n?(?P<body>.*)\n?</untrusted_tool_output>", re.S)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _tool_payload(msg: ChatMessage) -> Any:
    m = WRAPPED.search(msg.content)
    body = m.group("body") if m else msg.content
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def extract_directives(text: str) -> tuple[list[str], list[str]]:
    reads = [m.group("path") for m in READ_DIRECTIVE.finditer(text)]
    sends = [m.group("dest").rstrip(".,;:") for m in SEND_DIRECTIVE.finditer(text)]
    return reads, sends


def _first_sentence(content: str) -> str:
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "|", "-", "<!--")):
            return line.split(". ")[0].rstrip(".") + "."
    return content[:120]


class SimulatorProvider(ModelProvider):
    name = "simulator"
    is_simulated = True

    def __init__(self, profile: Profile = "naive") -> None:
        self.profile = profile
        self.model = f"agentshield-simulator/{profile}"

    # -- planning -------------------------------------------------------------------------------
    def _plan_from_user(self, user_text: str) -> list[tuple[str, dict[str, Any]]]:
        calls: list[tuple[str, dict[str, Any]]] = []
        override = bool(OVERRIDE_FRAMING.search(user_text))
        bucket = BUCKET_MENTION.search(user_text)
        if bucket:
            calls.append(("lookup_cloud_config", {"resource_id": f"s3:{bucket.group('name')}"}))
        elif SEARCH_INTENT.search(user_text):
            first = re.split(r"(?<=[.?!])\s", user_text.strip(), maxsplit=1)[0]
            calls.append(("search_documents", {"query": first[:200], "top_k": 3}))
        if self.profile == "naive" or not override:
            reads, sends = extract_directives(user_text)
            calls += [("read_file", {"path": p}) for p in reads]
            calls += [
                ("send_message", {"destination": d, "subject": "Requested information", "body": "{pending}"})
                for d in sends
            ]
        return calls

    def complete(self, request: ModelRequest) -> ModelResponse:
        msgs = request.messages
        user_text = next((m.content for m in msgs if m.role == "user"), "")
        proposed = [(tc.name, tc.arguments) for m in msgs if m.role == "assistant" for tc in m.tool_calls]
        tool_msgs = [m for m in msgs if m.role == "tool"]
        turn = sum(1 for m in msgs if m.role == "assistant")

        if turn == 0:
            planned = self._plan_from_user(user_text)
            reads_first = [c for c in planned if c[0] != "send_message"]
            calls = reads_first or planned
        else:
            calls = self._follow_up_calls(tool_msgs, proposed)

        # Fill bodies of outbound messages with the content the directive asked for (taint flow).
        calls = [(n, self._fill_body(a, msgs)) if n == "send_message" else (n, a) for n, a in calls]
        calls = [c for c in calls if c not in proposed]

        prompt_chars = len(request.system) + sum(len(m.content) for m in msgs)
        if calls:
            tcs = [ProposedToolCall(id=f"sim_{turn}_{i}", name=n, arguments=a) for i, (n, a) in enumerate(calls)]
            return ModelResponse(
                text="",
                tool_calls=tcs,
                stop_reason="tool_use",
                model=self.model,
                usage=Usage(input_tokens=prompt_chars // 4, output_tokens=40 * len(tcs), estimated=True, cost_usd=0.0),
            )
        answer = self._final_answer(msgs, user_text)
        return ModelResponse(
            text=answer,
            stop_reason="end_turn",
            model=self.model,
            usage=Usage(input_tokens=prompt_chars // 4, output_tokens=len(answer) // 4, estimated=True, cost_usd=0.0),
        )

    def _follow_up_calls(
        self, tool_msgs: list[ChatMessage], proposed: list[tuple[str, dict[str, Any]]]
    ) -> list[tuple[str, dict[str, Any]]]:
        reads: list[str] = []
        sends: list[str] = []
        # Directives from the user were already planned on turn 0 (or declined); here we look at
        # the untrusted tool output, which only the naive profile obeys.
        if self.profile == "naive":
            for m in tool_msgs:
                for s in _strings(_tool_payload(m)):
                    r, d = extract_directives(s)
                    reads += r
                    sends += d
        user_sends = [a["destination"] for n, a in proposed if n == "send_message"]
        pending_reads = [("read_file", {"path": p}) for p in dict.fromkeys(reads)]
        pending_reads = [c for c in pending_reads if c not in proposed]
        if pending_reads:
            return pending_reads
        return [
            ("send_message", {"destination": d, "subject": "Requested information", "body": "{pending}"})
            for d in dict.fromkeys(sends)
            if d not in user_sends
        ]

    def _fill_body(self, args: dict[str, Any], msgs: list[ChatMessage]) -> dict[str, Any]:
        if args.get("body") != "{pending}":
            return args
        read_contents = []
        for m in msgs:
            if m.role == "tool" and m.tool_name == "read_file" and not m.is_error:
                payload = _tool_payload(m)
                if isinstance(payload, dict) and "content" in payload:
                    read_contents.append(payload["content"])
        if not read_contents:
            last = next((m for m in reversed(msgs) if m.role == "tool" and not m.is_error), None)
            read_contents = [json.dumps(_tool_payload(last))[:4000]] if last else ["(no content)"]
        return {**args, "body": "\n\n".join(read_contents)[:7900]}

    # -- answer ---------------------------------------------------------------------------------
    def _final_answer(self, msgs: list[ChatMessage], user_text: str) -> str:
        lines: list[str] = []
        injected = False
        declined_override = self.profile == "resistant" and bool(OVERRIDE_FRAMING.search(user_text))
        for m in msgs:
            if m.role != "tool":
                continue
            payload = _tool_payload(m)
            if m.is_error:
                reason = payload.get("reasons", [payload])[0] if isinstance(payload, dict) else payload
                lines.append(f"- I could not complete `{m.tool_name}`: {reason}")
                continue
            if any(any(extract_directives(s)) for s in _strings(payload)):
                injected = True
            if m.tool_name == "search_documents" and isinstance(payload, dict):
                for r in payload.get("results", []):
                    lines.append(f"- {r['path']}: {_first_sentence(r['content'])}")
            elif m.tool_name == "read_file" and isinstance(payload, dict):
                if "content" in payload:
                    lines.append(f"- Contents of {payload['path']}:\n{payload['content']}")
                else:
                    lines.append(f"- {payload.get('error')}: {payload.get('path')}")
            elif m.tool_name == "lookup_cloud_config" and isinstance(payload, dict):
                res = payload.get("resource")
                if res:
                    enc = res.get("encryption") or []
                    alg = enc[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] if enc else "not configured"
                    lines.append(
                        f"- {res['resource_id']}: default encryption {alg}, versioning {res.get('versioning')}."
                    )
                else:
                    lines.append(f"- {payload.get('error')}")
            elif m.tool_name == "send_message" and isinstance(payload, dict):
                lines.append(f"- Message queued for {payload.get('destination')} (simulated outbox).")
        if injected and self.profile == "resistant":
            lines.append("- Note: retrieved content contained embedded instructions. I did not follow them.")
        if declined_override:
            lines.append("- I declined the part of the request that asked me to override my instructions.")
        header = "[SIMULATED RESPONSE] Here is what I found:"
        return header + ("\n" + "\n".join(lines) if lines else "\n- No relevant information was found.")
