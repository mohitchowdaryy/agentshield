"""Cloud-to-agent risk correlation.

Each rule joins persisted cloud findings / resources with an agent profile and red-team runs and
records exactly which evidence it used. Status values:

  modeled                            Preconditions exist in configuration; no step was exercised.
  agent_step_observed_in_simulation  The agent-side step (untrusted content steering the agent's
                                     tool use) was observed in a sandboxed red-team run. The cloud
                                     step was NOT exercised; nothing here is a proven attack path.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentshield.cloud import iam_policy
from agentshield.models import Agent, Finding, Resource, RiskCorrelation, TestRun, utcnow

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _steering_runs(runs: list[TestRun], tool: str | None = None) -> list[TestRun]:
    """Runs where the model proposed an unsafe call after seeing an injected payload."""
    out = []
    for r in runs:
        ev = r.evaluation or {}
        props = ev.get("unsafe_proposals", [])
        if ev.get("checks", {}).get("saw_malicious_content") and props:
            if tool is None or any(p.get("tool") == tool for p in props):
                out.append(r)
    return out


def _run_ref(r: TestRun) -> dict[str, Any]:
    return {
        "run_id": r.id,
        "scenario": r.scenario_fk,
        "mode": r.policy_mode,
        "provider": r.provider,
        "is_simulated": r.is_simulated,
        "outcome": r.outcome,
    }


def _upsert(session: Session, fingerprint: str, **fields: Any) -> RiskCorrelation:
    row = session.scalar(select(RiskCorrelation).where(RiskCorrelation.fingerprint == fingerprint))
    if row is None:
        row = RiskCorrelation(fingerprint=fingerprint)
        session.add(row)
    for k, v in fields.items():
        setattr(row, k, v)
    row.updated_at = utcnow()
    return row


def _node(nid: str, kind: str, label: str, **extra: Any) -> dict[str, Any]:
    return {"id": nid, "type": kind, "label": label, **extra}


def _edge(src: str, dst: str, label: str, status: str) -> dict[str, Any]:
    return {"source": src, "target": dst, "label": label, "status": status}


def compute_correlations(session: Session) -> list[RiskCorrelation]:
    produced: list[RiskCorrelation] = []
    seen_fps: set[str] = set()
    agents = session.scalars(select(Agent)).all()
    open_findings = session.scalars(select(Finding).where(Finding.status == "open")).all()

    for agent in agents:
        runs = session.scalars(select(TestRun).where(TestRun.agent_fk == agent.id)).all()
        steering = _steering_runs(list(runs))
        status = "agent_step_observed_in_simulation" if steering else "modeled"
        identity = agent.cloud_identity_arn
        tools = sorted(agent.profile.get("resolved_policies", {}).get("protected", {}).get("allowed_tools", []))

        # CORR-001: excessive permissions on the agent's own cloud identity.
        iam_findings = [
            f
            for f in open_findings
            if identity and f.resource_arn == identity and f.rule_id in ("AWS-IAM-001", "AWS-IAM-002")
        ]
        if iam_findings:
            worst = min((f.severity for f in iam_findings), key=lambda s: SEV_RANK[s])
            fp = _fp("CORR-001", agent.id, identity or "")
            seen_fps.add(fp)
            produced.append(
                _upsert(
                    session,
                    fp,
                    rule_id="CORR-001",
                    title=f"Prompt-injectable agent '{agent.name}' runs with an over-privileged cloud identity",
                    severity="critical" if worst == "critical" else "high",
                    status=status,
                    agent_fk=agent.id,
                    finding_ids=[f.id for f in iam_findings],
                    run_ids=[r.id for r in steering],
                    evidence={
                        "agent_identity": identity,
                        "iam_findings": [
                            {"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity}
                            for f in iam_findings
                        ],
                        "agent_tools": tools,
                        "steering_runs": [_run_ref(r) for r in steering],
                        "not_validated": [
                            "The sandboxed agent tools do not use AWS credentials; no AWS API call was attempted.",
                            "Effective permissions (SCPs, boundaries, session policies) were not evaluated.",
                        ],
                    },
                    path={
                        "nodes": [
                            _node("entry", "entry", "Untrusted content (document / tool output)"),
                            _node("agent", "agent", agent.name),
                            _node("identity", "identity", identity.split("/")[-1] if identity else "?", arn=identity),
                            _node("blast", "resource", "Account resources reachable by wildcard grants"),
                        ],
                        "edges": [
                            _edge(
                                "entry", "agent", "steers tool use", "observed_in_simulation" if steering else "modeled"
                            ),
                            _edge("agent", "identity", "acts as", "configured"),
                            _edge("identity", "blast", ", ".join(sorted({f.rule_id for f in iam_findings})), "modeled"),
                        ],
                    },
                    explanation=(
                        f"The agent's IAM role has {len(iam_findings)} excessive-permission finding(s). "
                        + (
                            f"In {len(steering)} sandboxed run(s) injected content made the model propose unsafe tool "
                            "calls, so a compromise of the agent's decision-making is plausible. "
                            if steering
                            else "No red-team run has yet shown the model being steered. "
                        )
                        + "If the agent's tools used this role, the blast radius of such a compromise would include "
                        "everything the wildcard grants reach. This is a modeled path; "
                        "the cloud step was not exercised."
                    ),
                )
            )

        # CORR-002: the agent's retrieval corpus lives in a bucket with a public bucket policy.
        sources = agent.profile.get("data_sources", [])
        for src in sources:
            bucket_findings = [
                f
                for f in open_findings
                if f.resource_arn == src.get("arn") and f.rule_id == "AWS-S3-003" and f.severity != "low"
            ]
            if not bucket_findings:
                continue
            f = bucket_findings[0]
            actions = f.evidence.get("public_actions", [])
            writable = iam_policy.action_matches(actions, "s3:PutObject")
            idx_steering = [r for r in steering if r.scenario_fk == "indirect-injection"]
            fp = _fp("CORR-002", agent.id, src.get("arn", ""))
            seen_fps.add(fp)
            produced.append(
                _upsert(
                    session,
                    fp,
                    rule_id="CORR-002",
                    title=(
                        f"Agent retrieval corpus is publicly {'writable' if writable else 'readable'}: "
                        f"{src.get('arn', '').split(':::')[-1]}"
                    ),
                    severity="critical" if writable else "medium",
                    status="agent_step_observed_in_simulation" if (writable and idx_steering) else "modeled",
                    agent_fk=agent.id,
                    finding_ids=[f.id],
                    run_ids=[r.id for r in idx_steering],
                    evidence={
                        "data_source": src,
                        "bucket_finding": {
                            "id": f.id,
                            "rule_id": f.rule_id,
                            "severity": f.severity,
                            "public_actions": actions,
                        },
                        "public_write": writable,
                        "indirect_injection_runs": [_run_ref(r) for r in idx_steering],
                    },
                    path={
                        "nodes": [
                            _node("public", "entry", "Anyone on the internet"),
                            _node("bucket", "resource", src.get("arn", "").split(":::")[-1], arn=src.get("arn")),
                            _node("agent", "agent", agent.name),
                        ],
                        "edges": (
                            [
                                _edge("public", "bucket", "s3:PutObject (plant payload)", "modeled"),
                                _edge(
                                    "bucket",
                                    "agent",
                                    "retrieved as untrusted content",
                                    "observed_in_simulation" if idx_steering else "modeled",
                                ),
                            ]
                            if writable
                            else [
                                _edge("public", "bucket", "s3:GetObject (" + ", ".join(actions) + ")", "modeled"),
                                _edge("bucket", "agent", "corpus used for retrieval", "configured"),
                            ]
                        ),
                    },
                    explanation=(
                        "The bucket that backs the agent's retrieval corpus has a bucket policy granting "
                        f"{', '.join(actions) or 'access'} to any principal. "
                        + (
                            "Public write access would let anyone plant documents the agent retrieves, "
                            "the entry point "
                            "exercised by the indirect-injection scenario."
                            if writable
                            else "Public read exposes every document the agent can retrieve, and anything "
                            "written into the "
                            "corpus, to the internet. It also lets an attacker study the corpus to craft injection "
                            "payloads. Public write was not found, so the bucket is not itself an "
                            "injection entry point."
                        )
                    ),
                )
            )

        # CORR-003: the agent identity can read buckets classified confidential.
        if identity:
            role = session.scalar(select(Resource).where(Resource.arn == identity))
            if role is not None:
                attrs = role.attributes
                docs = list((attrs.get("inline_policies") or {}).values()) + [
                    p["document"] for p in attrs.get("attached_policies") or [] if p.get("document")
                ]
                buckets = session.scalars(select(Resource).where(Resource.resource_type == "AWS::S3::Bucket")).all()
                for b in buckets:
                    if (b.attributes.get("tags") or {}).get("data-classification") != "confidential":
                        continue
                    allowed, stmts = iam_policy.allows(docs, "s3:GetObject", f"{b.arn}/*")
                    if not allowed:
                        continue
                    read_steering = _steering_runs(list(runs), tool="read_file")
                    fp = _fp("CORR-003", agent.id, b.arn)
                    seen_fps.add(fp)
                    produced.append(
                        _upsert(
                            session,
                            fp,
                            rule_id="CORR-003",
                            title=f"Agent identity can read confidential bucket '{b.name}'",
                            severity="high",
                            status="agent_step_observed_in_simulation" if read_steering else "modeled",
                            agent_fk=agent.id,
                            finding_ids=[f.id for f in open_findings if f.resource_arn == identity],
                            run_ids=[r.id for r in read_steering],
                            evidence={
                                "identity": identity,
                                "bucket": b.arn,
                                "classification_tag": "confidential",
                                "static_policy_check": {
                                    "action": "s3:GetObject",
                                    "resource": f"{b.arn}/*",
                                    "allowed_by_statements": stmts,
                                },
                                "confidential_read_attempt_runs": [_run_ref(r) for r in read_steering],
                                "limitations": "Static identity-policy analysis; conditions, SCPs, permission "
                                "boundaries and the bucket's own policy/KMS key policy not evaluated.",
                            },
                            path={
                                "nodes": [
                                    _node("entry", "entry", "Injected instruction"),
                                    _node("agent", "agent", agent.name),
                                    _node("identity", "identity", identity.split("/")[-1], arn=identity),
                                    _node("bucket", "resource", b.name, arn=b.arn),
                                ],
                                "edges": [
                                    _edge(
                                        "entry",
                                        "agent",
                                        "requests confidential read",
                                        "observed_in_simulation" if read_steering else "modeled",
                                    ),
                                    _edge("agent", "identity", "acts as", "configured"),
                                    _edge("identity", "bucket", "s3:GetObject allowed (static)", "modeled"),
                                ],
                            },
                            explanation=(
                                f"Static analysis of the agent role's policies finds s3:GetObject allowed on "
                                f"'{b.name}', which is tagged data-classification=confidential. "
                                + (
                                    f"{len(read_steering)} sandboxed run(s) showed injected content making the model "
                                    "request confidential file reads. "
                                    if read_steering
                                    else ""
                                )
                                + "Scope the role to the knowledge-base bucket so a steered agent cannot reach it."
                            ),
                        )
                    )

    # Correlations whose preconditions disappeared are removed so the view reflects current evidence.
    for row in session.scalars(select(RiskCorrelation)).all():
        if row.fingerprint not in seen_fps:
            session.delete(row)
    session.flush()
    return produced
