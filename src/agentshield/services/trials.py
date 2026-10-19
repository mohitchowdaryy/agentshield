"""Repeated trials: run one scenario N times under identical settings and store per-outcome counts.

Counts are only meaningful for a stochastic target (a live model). The simulator is deterministic, so
its N trials are identical; the trial set records `is_simulated` so that is never mistaken for a rate.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from agentshield.agent.gateway import Approver
from agentshield.agent.policy import PolicyMode
from agentshield.agent.providers.base import ModelProvider
from agentshield.models import TestRun, TrialSet, utcnow
from agentshield.redteam.engine import run_scenario
from agentshield.redteam.scenarios import Scenario
from agentshield.services.redteam import persist_run, sync_agents, sync_scenarios

MAX_TRIALS = 50
OUTCOMES = ("succeeded", "failed", "inconclusive", "errored")


def summarize(runs: list[TestRun]) -> tuple[dict[str, int], dict[str, int]]:
    """Outcome counts and per-check counts (booleans counted when true, integers summed)."""
    outcomes: Counter[str] = Counter({o: 0 for o in OUTCOMES})
    checks: Counter[str] = Counter()
    for r in runs:
        outcomes[r.outcome or "errored"] += 1
        for k, v in ((r.evaluation or {}).get("checks") or {}).items():
            if isinstance(v, bool):
                checks[k] += int(v)
            elif isinstance(v, int):
                checks[k] += v
    return dict(outcomes), dict(checks)


def run_trials(
    session: Session,
    scenario: Scenario,
    provider: ModelProvider,
    mode: PolicyMode,
    trials: int,
    approver: Approver | None = None,
) -> TrialSet:
    if not 1 <= trials <= MAX_TRIALS:
        raise ValueError(f"trials must be between 1 and {MAX_TRIALS}")
    sync_agents(session)
    sync_scenarios(session)
    trial_set = TrialSet(
        scenario_fk=scenario.id,
        agent_fk="support-agent",
        policy_mode=mode,
        provider=provider.name,
        model=provider.model,
        is_simulated=provider.is_simulated,
        trials=trials,
    )
    session.add(trial_set)
    session.flush()
    runs: list[TestRun] = []
    for i in range(trials):
        result = run_scenario(scenario, provider, mode, approver=approver)
        run = persist_run(session, result, batch_id=trial_set.id)
        run.trial_set_fk, run.trial_index = trial_set.id, i + 1
        runs.append(run)
    trial_set.agent_fk = runs[0].agent_fk
    trial_set.outcome_counts, trial_set.check_counts = summarize(runs)
    trial_set.run_ids = [r.id for r in runs]
    trial_set.finished_at = utcnow()
    session.flush()
    return trial_set


def trial_set_dict(t: TrialSet) -> dict[str, Any]:
    from agentshield.services.queries import _iso

    return {
        "id": t.id,
        "scenario_id": t.scenario_fk,
        "scenario_name": t.scenario.name if t.scenario else t.scenario_fk,
        "policy_mode": t.policy_mode,
        "provider": t.provider,
        "model": t.model,
        "is_simulated": t.is_simulated,
        "trials": t.trials,
        "outcome_counts": t.outcome_counts,
        "check_counts": t.check_counts,
        "run_ids": t.run_ids,
        "created_at": _iso(t.created_at),
        "finished_at": _iso(t.finished_at),
    }
