"""Persist agents, scenarios and red-team runs (interactions, attempts, decisions, evidence events)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from agentshield.agent.policy import load_agent_profiles
from agentshield.models import (
    Agent,
    AuthorizationDecision,
    EvidenceEvent,
    ModelInteraction,
    TestRun,
    TestScenario,
    ToolCallAttempt,
    utcnow,
)
from agentshield.redaction import redact
from agentshield.redteam.engine import RunResult
from agentshield.redteam.scenarios import SCENARIOS


def sync_agents(session: Session) -> None:
    for profile in load_agent_profiles():
        row = session.get(Agent, profile.id) or Agent(id=profile.id)
        row.name, row.description = profile.name, profile.description
        row.cloud_identity_arn = profile.cloud_identity_arn
        data = profile.model_dump()
        data["resolved_policies"] = {m: profile.load_policy(m).model_dump() for m in profile.policies}  # type: ignore[arg-type]
        row.profile = data
        session.merge(row)


def sync_scenarios(session: Session) -> None:
    for s in SCENARIOS.values():
        row = session.get(TestScenario, s.id) or TestScenario(id=s.id)
        definition = s.model_dump()
        if row.definition != definition:
            row.updated_at = utcnow()
        row.name, row.category, row.severity, row.version = s.name, s.category, s.severity, s.version
        row.definition = definition
        session.merge(row)


def _ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def persist_run(session: Session, result: RunResult, batch_id: str | None = None) -> TestRun:
    sync_agents(session)
    sync_scenarios(session)
    session.flush()
    t = result.trace
    started = _ts(t.events[1].at) if len(t.events) > 1 else utcnow()
    run = TestRun(
        batch_id=batch_id,
        scenario_fk=result.scenario.id,
        agent_fk=result.agent.id,
        policy_mode=t.policy_mode,
        provider=t.provider,
        model=t.model,
        is_simulated=t.is_simulated,
        status="errored" if t.status == "errored" else "completed",
        outcome=result.evaluation["outcome"],
        evaluation=redact({**result.evaluation, "outbox": t.outbox, "run_status": t.status}),
        final_answer=redact(t.final_answer) if t.final_answer else None,
        usage=t.usage,
        error=redact(t.error) if t.error else None,
        started_at=started,
        finished_at=utcnow(),
    )
    session.add(run)
    session.flush()

    interaction_ids: dict[int, str] = {}
    for i in t.interactions:
        mi = ModelInteraction(
            run_fk=run.id,
            turn=i.turn,
            request=redact(i.request),
            response=redact(i.response),
            input_tokens=i.input_tokens,
            output_tokens=i.output_tokens,
            cost_usd=i.cost_usd,
            latency_ms=i.latency_ms,
        )
        session.add(mi)
        session.flush()
        interaction_ids[i.turn] = mi.id

    for a in t.attempts:
        attempt = ToolCallAttempt(
            run_fk=run.id,
            interaction_fk=interaction_ids.get(a.turn),
            seq=a.seq,
            turn=a.turn,
            tool_name=a.tool_name,
            arguments=redact(a.arguments),
            untrusted_context=a.untrusted_context,
            executed=a.executed,
            result=redact(a.result) if a.result is not None else None,
            error=a.error,
            proposed_at=_ts(a.proposed_at),
            executed_at=_ts(a.executed_at),
        )
        attempt.decision = AuthorizationDecision(
            decision=a.decision,
            policy_mode=t.policy_mode,
            rule_ids=a.rule_ids,
            reasons=redact(a.reasons),
            approval=a.approval,
        )
        session.add(attempt)

    for e in t.events:
        session.add(
            EvidenceEvent(
                run_fk=run.id,
                seq=e.seq,
                event_type=e.event_type,
                trust=e.trust,
                payload=redact(e.payload),
                created_at=_ts(e.at),
            )
        )
    session.flush()
    return run
