"""Offline demonstration: demo cloud scan + simulated red-team matrix + correlation. No credentials needed."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from agentshield.agent.providers.simulator import SimulatorProvider
from agentshield.cloud.demo import DemoCollector
from agentshield.correlation.engine import compute_correlations
from agentshield.models import new_id
from agentshield.redteam.engine import run_scenario
from agentshield.redteam.scenarios import SCENARIOS
from agentshield.services.redteam import persist_run, sync_agents, sync_scenarios
from agentshield.services.scans import run_scan

# (simulator profile, policy mode): the vulnerable baseline, the gateway, and a resistant model.
DEMO_MATRIX = [("naive", "vulnerable"), ("naive", "protected"), ("resistant", "protected")]


def run_demo(session: Session) -> dict[str, Any]:
    sync_agents(session)
    sync_scenarios(session)
    scan = run_scan(session, DemoCollector())
    batch = new_id("batch")
    runs = []
    for scenario in SCENARIOS.values():
        for profile, mode in DEMO_MATRIX:
            result = run_scenario(scenario, SimulatorProvider(profile), mode)  # type: ignore[arg-type]
            run = persist_run(session, result, batch_id=batch)
            runs.append(
                {"id": run.id, "scenario": scenario.id, "profile": profile, "mode": mode, "outcome": run.outcome}
            )
    correlations = compute_correlations(session)
    return {
        "scan_id": scan.id,
        "scan_summary": scan.summary,
        "batch_id": batch,
        "runs": runs,
        "correlations": [c.id for c in correlations],
    }
