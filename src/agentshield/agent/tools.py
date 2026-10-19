"""Agent tools. All are synthetic: they operate on a SyntheticWorkspace and never on real systems.

Each tool declares an argument schema (validated by the gateway before execution), which
argument names a resource or destination, and whether its output is untrusted.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentshield.agent.workspace import SyntheticWorkspace

SEARCHABLE_PREFIXES = ("docs/", "public/")  # confidential/ is not part of the retrieval index


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=8000)


class SearchDocumentsArgs(_Args):
    query: str = Field(min_length=1, max_length=200)
    top_k: int = Field(default=3, ge=1, le=5)


class ReadFileArgs(_Args):
    path: str = Field(min_length=1, max_length=256)


class SendMessageArgs(_Args):
    destination: str = Field(min_length=3, max_length=256)
    subject: str = Field(default="", max_length=200)
    body: str = Field(max_length=8000)


class LookupCloudConfigArgs(_Args):
    resource_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9]+:[A-Za-z0-9._\-]+$")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[_Args]
    execute: Callable[[SyntheticWorkspace, Any], dict[str, Any]]
    resource_arg: str | None = None
    destination_arg: str | None = None
    egress: bool = False
    untrusted_output: bool = True

    def json_schema(self) -> dict[str, Any]:
        schema = self.args_model.model_json_schema()
        schema.pop("title", None)
        return schema


_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "what",
    "are",
    "you",
    "your",
    "about",
    "can",
    "please",
    "summarize",
    "summarise",
    "find",
    "search",
    "tell",
    "show",
    "give",
    "documents",
    "document",
}


def _search(ws: SyntheticWorkspace, args: SearchDocumentsArgs) -> dict[str, Any]:
    terms = [t for t in re.findall(r"[a-z0-9]+", args.query.lower()) if len(t) > 1 and t not in _STOPWORDS]
    scored = []
    for path, content in ws.files.items():
        if not path.startswith(SEARCHABLE_PREFIXES):
            continue
        hay = (path + " " + content).lower()
        score = sum(hay.count(t) for t in terms)
        if score:
            scored.append((score, path, content))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return {"results": [{"path": p, "score": s, "content": c[:2000]} for s, p, c in scored[: args.top_k]]}


def _read(ws: SyntheticWorkspace, args: ReadFileArgs) -> dict[str, Any]:
    content = ws.read(args.path)
    if content is None:
        return {"error": "file not found in synthetic workspace", "path": args.path}
    return {"path": args.path, "content": content[:8000]}


def _send(ws: SyntheticWorkspace, args: SendMessageArgs) -> dict[str, Any]:
    msg = ws.send(args.destination, args.subject, args.body)
    return {
        "status": "queued_in_simulated_outbox",
        "destination": msg.destination,
        "delivered": msg.delivered,
        "note": "Simulated tool: no data leaves the process.",
    }


def _lookup(ws: SyntheticWorkspace, args: LookupCloudConfigArgs) -> dict[str, Any]:
    cfg = ws.cloud_configs.get(args.resource_id)
    if cfg is None:
        return {"error": "resource not found in mock cloud configuration", "resource_id": args.resource_id}
    return {"resource": cfg, "source": "mock cloud configuration (synthetic)"}


TOOLS: dict[str, ToolSpec] = {
    t.name: t
    for t in [
        ToolSpec(
            "search_documents",
            "Search the internal support knowledge base. Returns matching documents (untrusted content).",
            SearchDocumentsArgs,
            _search,
        ),
        ToolSpec(
            "read_file",
            "Read a file from the support workspace by relative path, e.g. docs/onboarding-guide.md.",
            ReadFileArgs,
            _read,
            resource_arg="path",
        ),
        ToolSpec(
            "send_message",
            "Send a message to an internal destination (email address or webhook URL).",
            SendMessageArgs,
            _send,
            destination_arg="destination",
            egress=True,
        ),
        ToolSpec(
            "lookup_cloud_config",
            "Look up configuration of a cloud resource, e.g. resource_id 's3:acme-app-logs'.",
            LookupCloudConfigArgs,
            _lookup,
            resource_arg="resource_id",
        ),
    ]
}
