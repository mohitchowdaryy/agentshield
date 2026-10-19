"""Read models shared by the API, CLI reports and exports. All metrics are counts over persisted rows."""

from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentshield.models import (
    Agent,
    AuthorizationDecision,
    Finding,
    FindingObservation,
    Resource,
    RiskCorrelation,
    Scan,
    TestRun,
    TestScenario,
    ToolCallAttempt,
)


def _iso(d: datetime | None) -> str | None:
    if d is None:
        return None
    # SQLite drops tzinfo; every timestamp is written in UTC.
    return (d if d.tzinfo else d.replace(tzinfo=UTC)).isoformat()


def finding_dict(f: Finding, detail: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "source": f.source,
        "account_id": f.account_id,
        "region": f.region,
        "resource_arn": f.resource_arn,
        "resource_type": f.resource_type,
        "risk_type": f.risk_type,
        "exploitability": f.exploitability,
        "remediation": f.remediation,
        "first_seen_at": _iso(f.first_seen_at),
        "last_seen_at": _iso(f.last_seen_at),
        "last_scan_id": f.last_scan_fk,
    }
    if detail:
        d["evidence"] = f.evidence
        d["references"] = f.references
    return d


def scan_dict(s: Scan) -> dict[str, Any]:
    return {
        "id": s.id,
        "source": s.source,
        "status": s.status,
        "account_id": s.account.account_id if s.account else None,
        "caller_arn": s.account.caller_arn if s.account else None,
        "regions": s.regions,
        "collection_gaps": s.collection_gaps,
        "summary": s.summary,
        "error": s.error,
        "started_at": _iso(s.started_at),
        "finished_at": _iso(s.finished_at),
    }


def run_summary(r: TestRun) -> dict[str, Any]:
    checks = (r.evaluation or {}).get("checks", {})
    return {
        "id": r.id,
        "batch_id": r.batch_id,
        "scenario_id": r.scenario_fk,
        "scenario_name": r.scenario.name if r.scenario else r.scenario_fk,
        "category": r.scenario.category if r.scenario else None,
        "agent_id": r.agent_fk,
        "policy_mode": r.policy_mode,
        "provider": r.provider,
        "model": r.model,
        "is_simulated": r.is_simulated,
        "status": r.status,
        "outcome": r.outcome,
        "defense_layer": (r.evaluation or {}).get("defense_layer"),
        "checks": checks,
        "usage": r.usage,
        "trial_set_id": r.trial_set_fk,
        "trial_index": r.trial_index,
        "started_at": _iso(r.started_at),
        "finished_at": _iso(r.finished_at),
    }


def run_detail(r: TestRun) -> dict[str, Any]:
    d = run_summary(r)
    d["scenario"] = r.scenario.definition if r.scenario else None
    d["evaluation"] = r.evaluation
    d["final_answer"] = r.final_answer
    d["error"] = r.error
    d["interactions"] = [
        {
            "id": i.id,
            "turn": i.turn,
            "request": i.request,
            "response": i.response,
            "input_tokens": i.input_tokens,
            "output_tokens": i.output_tokens,
            "cost_usd": i.cost_usd,
            "latency_ms": i.latency_ms,
            "created_at": _iso(i.created_at),
        }
        for i in r.interactions
    ]
    d["tool_calls"] = [
        {
            "id": a.id,
            "seq": a.seq,
            "turn": a.turn,
            "tool": a.tool_name,
            "arguments": a.arguments,
            "untrusted_context": a.untrusted_context,
            "executed": a.executed,
            "result": a.result,
            "error": a.error,
            "proposed_at": _iso(a.proposed_at),
            "executed_at": _iso(a.executed_at),
            "decision": {
                "decision": a.decision.decision,
                "rule_ids": a.decision.rule_ids,
                "reasons": a.decision.reasons,
                "approval": a.decision.approval,
                "policy_mode": a.decision.policy_mode,
            }
            if a.decision
            else None,
        }
        for a in r.attempts
    ]
    d["events"] = [
        {"seq": e.seq, "type": e.event_type, "trust": e.trust, "payload": e.payload, "at": _iso(e.created_at)}
        for e in r.events
    ]
    return d


def correlation_dict(c: RiskCorrelation) -> dict[str, Any]:
    return {
        "id": c.id,
        "rule_id": c.rule_id,
        "title": c.title,
        "severity": c.severity,
        "status": c.status,
        "agent_id": c.agent_fk,
        "finding_ids": c.finding_ids,
        "run_ids": c.run_ids,
        "evidence": c.evidence,
        "path": c.path,
        "explanation": c.explanation,
        "created_at": _iso(c.created_at),
        "updated_at": _iso(c.updated_at),
    }


def agent_dict(a: Agent) -> dict[str, Any]:
    return {
        "id": a.id,
        "name": a.name,
        "description": a.description,
        "cloud_identity_arn": a.cloud_identity_arn,
        "profile": a.profile,
    }


def scenario_dict(s: TestScenario) -> dict[str, Any]:
    return {
        "id": s.id,
        "name": s.name,
        "category": s.category,
        "severity": s.severity,
        "version": s.version,
        "definition": s.definition,
        "updated_at": _iso(s.updated_at),
    }


def overview(session: Session) -> dict[str, Any]:
    open_f = session.scalars(select(Finding).where(Finding.status == "open")).all()
    runs = session.scalars(select(TestRun)).all()
    decisions = session.scalars(select(AuthorizationDecision)).all()
    last_scan = session.scalar(select(Scan).order_by(Scan.started_at.desc()).limit(1))
    deny_rules: Counter[str] = Counter()
    for d in decisions:
        if d.decision == "deny":
            deny_rules.update(d.rule_ids)
    outcome_by_mode: dict[str, Counter[str]] = {}
    for r in runs:
        outcome_by_mode.setdefault(r.policy_mode, Counter())[r.outcome or "unknown"] += 1
    return {
        "findings": {
            "open": len(open_f),
            "resolved": session.scalar(select(func.count()).select_from(Finding).where(Finding.status == "resolved")),
            "by_severity": dict(Counter(f.severity for f in open_f)),
            "by_source": dict(Counter(f.source for f in open_f)),
            "by_rule": dict(Counter(f.rule_id for f in open_f)),
        },
        "scans": {
            "total": session.scalar(select(func.count()).select_from(Scan)),
            "last": scan_dict(last_scan) if last_scan else None,
        },
        "resources": session.scalar(select(func.count()).select_from(Resource)),
        "observations": session.scalar(select(func.count()).select_from(FindingObservation)),
        "redteam": {
            "runs": len(runs),
            "simulated_runs": sum(1 for r in runs if r.is_simulated),
            "live_model_runs": sum(1 for r in runs if not r.is_simulated),
            "by_outcome": dict(Counter(r.outcome or "unknown" for r in runs)),
            "by_mode_outcome": {m: dict(c) for m, c in outcome_by_mode.items()},
            "scenarios": session.scalar(select(func.count()).select_from(TestScenario)),
        },
        "gateway": {
            "tool_call_attempts": session.scalar(select(func.count()).select_from(ToolCallAttempt)),
            "allowed": sum(1 for d in decisions if d.decision == "allow"),
            "denied": sum(1 for d in decisions if d.decision == "deny"),
            "denials_by_rule": dict(deny_rules),
            "executed": session.scalar(
                select(func.count()).select_from(ToolCallAttempt).where(ToolCallAttempt.executed.is_(True))
            ),
        },
        "correlations": {
            "total": session.scalar(select(func.count()).select_from(RiskCorrelation)),
            "by_status": dict(Counter(c.status for c in session.scalars(select(RiskCorrelation)).all())),
        },
    }


FINDING_CSV_FIELDS = [
    "id",
    "rule_id",
    "title",
    "severity",
    "status",
    "source",
    "account_id",
    "region",
    "resource_arn",
    "resource_type",
    "risk_type",
    "exploitability",
    "first_seen_at",
    "last_seen_at",
    "remediation",
    "fingerprint",
]
RUN_CSV_FIELDS = [
    "id",
    "scenario_id",
    "policy_mode",
    "provider",
    "model",
    "is_simulated",
    "status",
    "outcome",
    "defense_layer",
    "saw_malicious_content",
    "unsafe_tool_call_proposed",
    "unsafe_calls_denied_by_gateway",
    "simulated_violation_executed",
    "legitimate_task_completed",
    "started_at",
]


def to_csv(rows: list[dict[str, Any]], fields: list[str]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        flat = {**r, **r.get("checks", {})}
        # Neutralize spreadsheet formula injection in exported text.
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in flat.items()})
    return buf.getvalue()
