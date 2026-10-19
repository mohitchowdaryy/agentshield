"""Gateway policy configuration and agent profiles. Policies are data files, never part of prompts."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

PolicyMode = Literal["protected", "vulnerable"]


class ToolRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_scopes: list[str] | None = None
    destinations: list[str] | None = None
    requires_approval: bool = False
    max_calls: int | None = Field(default=None, ge=0)


class AgentPolicy(BaseModel):
    model_config = ConfigDict(extra="ignore")

    mode: PolicyMode
    allowed_tools: list[str]
    tool_rules: dict[str, ToolRule] = Field(default_factory=dict)
    dlp_block_markers: list[str] = Field(default_factory=list)
    approval_when_untrusted_context: list[str] = Field(default_factory=list)
    # Only the vulnerable demo policy sets this. Tool-layer sandboxing still applies.
    skip_identifier_validation: bool = False


class DataSource(BaseModel):
    kind: str
    arn: str
    purpose: str = ""


class AgentProfile(BaseModel):
    id: str
    name: str
    description: str = ""
    cloud_identity_arn: str | None = None
    data_sources: list[DataSource] = Field(default_factory=list)
    policies: dict[str, str]

    def load_policy(self, mode: PolicyMode) -> AgentPolicy:
        return load_policy_file(self.policies[mode])


def _data_text(rel: str) -> str:
    node: Any = resources.files("agentshield.data")
    for part in rel.split("/"):
        node = node / part
    text: str = node.read_text(encoding="utf-8")
    return text


def load_policy_file(rel: str) -> AgentPolicy:
    return AgentPolicy.model_validate(json.loads(_data_text(rel)))


def load_agent_profiles() -> list[AgentProfile]:
    return [AgentProfile.model_validate(a) for a in json.loads(_data_text("agents.json"))]


def get_agent_profile(agent_id: str) -> AgentProfile:
    for a in load_agent_profiles():
        if a.id == agent_id:
            return a
    raise KeyError(f"unknown agent '{agent_id}'")
