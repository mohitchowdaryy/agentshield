"""Scenario runner: fresh sandbox per run, payload planted at the entry point, agent loop, evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentshield.agent.gateway import Approver, Gateway
from agentshield.agent.policy import AgentProfile, PolicyMode, get_agent_profile
from agentshield.agent.providers.base import ModelProvider
from agentshield.agent.runtime import AgentRuntime, RunTrace
from agentshield.agent.workspace import SyntheticWorkspace
from agentshield.config import get_settings
from agentshield.redteam.evaluator import evaluate
from agentshield.redteam.scenarios import Scenario


@dataclass
class RunResult:
    scenario: Scenario
    agent: AgentProfile
    trace: RunTrace
    evaluation: dict[str, Any]


def build_workspace(scenario: Scenario) -> SyntheticWorkspace:
    ws = SyntheticWorkspace.load_default()
    ws.files.update(scenario.overlay.files)
    for rid, tags in scenario.overlay.cloud_config_tags.items():
        ws.cloud_configs[rid]["tags"].update(tags)
    return ws


def run_scenario(
    scenario: Scenario,
    provider: ModelProvider,
    mode: PolicyMode = "protected",
    agent_id: str = "support-agent",
    approver: Approver | None = None,
    max_turns: int | None = None,
) -> RunResult:
    settings = get_settings()
    agent = get_agent_profile(agent_id)
    gateway = Gateway(agent.load_policy(mode), approver)
    runtime = AgentRuntime(
        provider,
        gateway,
        build_workspace(scenario),
        max_turns=max_turns or settings.max_agent_turns,
        max_output_tokens=settings.model_max_output_tokens,
    )
    trace = runtime.run(scenario.user_message)
    trace.events.insert(
        0,
        type(trace.events[0])(
            0,
            "scenario_setup",
            None,
            {
                "scenario_id": scenario.id,
                "entry_point": scenario.entry_point,
                "entry_point_detail": scenario.entry_point_detail,
                "policy_mode": mode,
                "provider": provider.name,
                "model": provider.model,
                "is_simulated": provider.is_simulated,
            },
        ),
    )
    return RunResult(scenario, agent, trace, evaluate(scenario, trace))
