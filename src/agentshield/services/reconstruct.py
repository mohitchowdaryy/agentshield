"""Rebuild a RunTrace from persisted rows so a run can be re-evaluated from stored evidence alone."""

from __future__ import annotations

from agentshield.agent.runtime import AttemptRecord, RunTrace
from agentshield.models import TestRun


def trace_from_run(run: TestRun) -> RunTrace:
    ev = run.evaluation or {}
    trace = RunTrace(provider=run.provider, model=run.model, is_simulated=run.is_simulated, policy_mode=run.policy_mode)
    trace.status = ev.get("run_status") or ("errored" if run.status == "errored" else "completed")
    trace.final_answer = run.final_answer
    trace.error = run.error
    trace.outbox = list(ev.get("outbox", []))
    seen: set[str] = set()
    for e in run.events:
        if e.event_type == "user_request":
            seen.add(e.payload.get("content", ""))
    for i in run.interactions:
        for m in i.request.get("messages", []):
            if m.get("role") in ("user", "tool"):
                seen.add(m.get("content", ""))
    trace.model_inputs = [s for s in seen if s]
    for a in run.attempts:
        d = a.decision
        trace.attempts.append(
            AttemptRecord(
                seq=a.seq,
                turn=a.turn,
                call_id=a.id,
                tool_name=a.tool_name,
                arguments=a.arguments,
                untrusted_context=a.untrusted_context,
                decision=d.decision if d else "deny",
                rule_ids=d.rule_ids if d else [],
                reasons=d.reasons if d else [],
                approval=d.approval if d else "",
                executed=a.executed,
                result=a.result,
                error=a.error,
            )
        )
    return trace
