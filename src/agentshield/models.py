"""Normalized relational schema. Changes here require an Alembic migration."""

from __future__ import annotations

import secrets
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Time-sortable, collision-resistant identifier, e.g. `run_0193a1b2c3d4e5f6a7b8c9d0`."""
    return f"{prefix}_{int(time.time() * 1000):012x}{secrets.token_hex(6)}"


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class CloudAccount(TimestampMixin, Base):
    __tablename__ = "cloud_accounts"
    __table_args__ = (UniqueConstraint("provider", "account_id", "source", name="uq_cloud_account"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("acct"))
    provider: Mapped[str] = mapped_column(String(16))
    account_id: Mapped[str] = mapped_column(String(64))
    caller_arn: Mapped[str | None] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(16))  # live | demo

    scans: Mapped[list[Scan]] = relationship(back_populates="account")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("scan"))
    account_fk: Mapped[str | None] = mapped_column(ForeignKey("cloud_accounts.id"))
    source: Mapped[str] = mapped_column(String(16))  # live | demo
    status: Mapped[str] = mapped_column(String(16))  # running | completed | partial | failed
    regions: Mapped[list[Any]] = mapped_column(default=list)
    collection_gaps: Mapped[list[Any]] = mapped_column(default=list)
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    account: Mapped[CloudAccount | None] = relationship(back_populates="scans")


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (UniqueConstraint("account_fk", "arn", name="uq_resource_arn"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("res"))
    account_fk: Mapped[str] = mapped_column(ForeignKey("cloud_accounts.id"))
    arn: Mapped[str] = mapped_column(String(1024))
    resource_type: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(512))
    region: Mapped[str] = mapped_column(String(32))
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)
    last_scan_fk: Mapped[str | None] = mapped_column(ForeignKey("scans.id"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("fnd"))
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | resolved
    source: Mapped[str] = mapped_column(String(16))  # live | demo
    account_id: Mapped[str] = mapped_column(String(64))
    region: Mapped[str] = mapped_column(String(32))
    resource_arn: Mapped[str] = mapped_column(String(1024))
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_fk: Mapped[str | None] = mapped_column(ForeignKey("resources.id"))
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    remediation: Mapped[str] = mapped_column(Text)
    risk_type: Mapped[str] = mapped_column(String(32), default="configuration")
    exploitability: Mapped[str] = mapped_column(String(32), default="not_validated")
    references: Mapped[list[Any]] = mapped_column(default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scan_fk: Mapped[str | None] = mapped_column(ForeignKey("scans.id"))


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    __table_args__ = (UniqueConstraint("finding_fk", "scan_fk", name="uq_observation"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("obs"))
    finding_fk: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    scan_fk: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(TimestampMixin, Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    cloud_identity_arn: Mapped[str | None] = mapped_column(String(512))
    profile: Mapped[dict[str, Any]] = mapped_column(default=dict)


class TestScenario(Base):
    __tablename__ = "test_scenarios"
    __test__ = False  # not a pytest test class

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    definition: Mapped[dict[str, Any]] = mapped_column(default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestRun(Base):
    __tablename__ = "test_runs"
    __test__ = False  # not a pytest test class

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("run"))
    batch_id: Mapped[str | None] = mapped_column(String(40), index=True)
    scenario_fk: Mapped[str] = mapped_column(ForeignKey("test_scenarios.id"))
    agent_fk: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    policy_mode: Mapped[str] = mapped_column(String(16))  # protected | vulnerable
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    is_simulated: Mapped[bool] = mapped_column(Boolean)
    status: Mapped[str] = mapped_column(String(16))  # running | completed | errored
    outcome: Mapped[str | None] = mapped_column(String(16))  # succeeded | failed | inconclusive | errored
    evaluation: Mapped[dict[str, Any]] = mapped_column(default=dict)
    final_answer: Mapped[str | None] = mapped_column(Text)
    usage: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    trial_set_fk: Mapped[str | None] = mapped_column(ForeignKey("trial_sets.id"), index=True)
    trial_index: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scenario: Mapped[TestScenario] = relationship()
    interactions: Mapped[list[ModelInteraction]] = relationship(
        back_populates="run", order_by="ModelInteraction.turn", cascade="all, delete-orphan"
    )
    attempts: Mapped[list[ToolCallAttempt]] = relationship(
        back_populates="run", order_by="ToolCallAttempt.seq", cascade="all, delete-orphan"
    )
    events: Mapped[list[EvidenceEvent]] = relationship(
        back_populates="run", order_by="EvidenceEvent.seq", cascade="all, delete-orphan"
    )


class TrialSet(Base):
    """N repeated runs of one scenario with the same provider, model and policy mode, plus their counts."""

    __tablename__ = "trial_sets"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("trials"))
    scenario_fk: Mapped[str] = mapped_column(ForeignKey("test_scenarios.id"), index=True)
    agent_fk: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    policy_mode: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    is_simulated: Mapped[bool] = mapped_column(Boolean)
    trials: Mapped[int] = mapped_column(Integer)
    # Outcome -> number of runs, e.g. {"succeeded": 3, "failed": 7}.
    outcome_counts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Evaluation check -> number of runs where it was true (numeric checks are summed).
    check_counts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    run_ids: Mapped[list[Any]] = mapped_column(default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scenario: Mapped[TestScenario] = relationship()


class ModelInteraction(Base):
    __tablename__ = "model_interactions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("mi"))
    run_fk: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    turn: Mapped[int] = mapped_column(Integer)
    request: Mapped[dict[str, Any]] = mapped_column(default=dict)
    response: Mapped[dict[str, Any]] = mapped_column(default=dict)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[float | None] = mapped_column(Float)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[TestRun] = relationship(back_populates="interactions")


class ToolCallAttempt(Base):
    __tablename__ = "tool_call_attempts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("tca"))
    run_fk: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    interaction_fk: Mapped[str | None] = mapped_column(ForeignKey("model_interactions.id"))
    seq: Mapped[int] = mapped_column(Integer)
    turn: Mapped[int] = mapped_column(Integer)
    tool_name: Mapped[str] = mapped_column(String(128))
    arguments: Mapped[dict[str, Any]] = mapped_column(default=dict)
    untrusted_context: Mapped[bool] = mapped_column(Boolean, default=False)
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    run: Mapped[TestRun] = relationship(back_populates="attempts")
    decision: Mapped[AuthorizationDecision | None] = relationship(
        back_populates="attempt", uselist=False, cascade="all, delete-orphan"
    )


class AuthorizationDecision(Base):
    __tablename__ = "authorization_decisions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("authz"))
    attempt_fk: Mapped[str] = mapped_column(ForeignKey("tool_call_attempts.id", ondelete="CASCADE"), unique=True)
    decision: Mapped[str] = mapped_column(String(8))  # allow | deny
    policy_mode: Mapped[str] = mapped_column(String(16))
    rule_ids: Mapped[list[Any]] = mapped_column(default=list)
    reasons: Mapped[list[Any]] = mapped_column(default=list)
    approval: Mapped[str] = mapped_column(String(16), default="not_required")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    attempt: Mapped[ToolCallAttempt] = relationship(back_populates="decision")


class EvidenceEvent(Base):
    __tablename__ = "evidence_events"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("evt"))
    run_fk: Mapped[str] = mapped_column(ForeignKey("test_runs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(48))
    trust: Mapped[str | None] = mapped_column(String(16))  # trusted | principal | untrusted
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[TestRun] = relationship(back_populates="events")


class IacScan(Base):
    """One static Infrastructure-as-Code scan (e.g. Checkov on a Terraform directory). Not live CSPM."""

    __tablename__ = "iac_scans"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("iacscan"))
    label: Mapped[str] = mapped_column(String(64))  # e.g. "insecure", "secure", or a directory name
    target: Mapped[str] = mapped_column(String(1024))  # path relative to the project when possible
    scanner: Mapped[str] = mapped_column(String(32))
    scanner_version: Mapped[str | None] = mapped_column(String(32))
    framework: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))  # completed | failed
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    command: Mapped[list[Any]] = mapped_column(default=list)
    parsing_errors: Mapped[list[Any]] = mapped_column(default=list)
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float | None] = mapped_column(Float)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    findings: Mapped[list[IacFinding]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class IacFinding(Base):
    """One check result from an IaC scan. Severity is stored only when the scanner reports it."""

    __tablename__ = "iac_findings"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("iacf"))
    scan_fk: Mapped[str] = mapped_column(ForeignKey("iac_scans.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    check_id: Mapped[str] = mapped_column(String(64), index=True)
    check_name: Mapped[str] = mapped_column(String(512))
    result: Mapped[str] = mapped_column(String(16), index=True)  # failed | passed | skipped
    resource: Mapped[str] = mapped_column(String(512), index=True)
    resource_type: Mapped[str] = mapped_column(String(128))
    file_path: Mapped[str] = mapped_column(String(1024))
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str | None] = mapped_column(String(16))  # None when the scanner reports none
    guideline: Mapped[str | None] = mapped_column(String(1024))
    remediation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)

    scan: Mapped[IacScan] = relationship(back_populates="findings")


class RiskCorrelation(Base):
    __tablename__ = "risk_correlations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("corr"))
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    rule_id: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32))  # modeled | observed_in_simulation
    agent_fk: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    finding_ids: Mapped[list[Any]] = mapped_column(default=list)
    run_ids: Mapped[list[Any]] = mapped_column(default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    path: Mapped[dict[str, Any]] = mapped_column(default=dict)
    explanation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
