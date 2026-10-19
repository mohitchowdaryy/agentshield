from sqlalchemy import func, select

from agentshield.agent.providers.simulator import SimulatorProvider
from agentshield.cloud.base import CloudInventory, RootAccountSummary
from agentshield.cloud.demo import DemoCollector
from agentshield.correlation.engine import compute_correlations
from agentshield.models import (
    AuthorizationDecision,
    EvidenceEvent,
    Finding,
    FindingObservation,
    ModelInteraction,
    RiskCorrelation,
    Scan,
    TestRun,
    ToolCallAttempt,
)
from agentshield.redteam.engine import run_scenario
from agentshield.redteam.scenarios import SCENARIOS
from agentshield.services.demo import run_demo
from agentshield.services.reconstruct import trace_from_run
from agentshield.services.redteam import persist_run
from agentshield.services.scans import persist_inventory, run_scan


def count(s, model):
    return s.scalar(select(func.count()).select_from(model))


def test_repeated_scans_deduplicate_findings(session):
    run_scan(session, DemoCollector())
    first = count(session, Finding)
    run_scan(session, DemoCollector())
    assert count(session, Finding) == first == 13
    assert count(session, FindingObservation) == 2 * first
    assert count(session, Scan) == 2


def test_gap_free_rescan_resolves_findings(session):
    inv = CloudInventory(
        account_id="123456789012",
        source="live",
        regions=["us-east-1"],
        root_account=RootAccountSummary(mfa_enabled=False),
    )
    persist_inventory(session, inv)
    f = session.scalar(select(Finding))
    assert f.rule_id == "AWS-ROOT-001" and f.status == "open"
    fixed = CloudInventory(
        account_id="123456789012",
        source="live",
        regions=["us-east-1"],
        root_account=RootAccountSummary(mfa_enabled=True),
    )
    scan = persist_inventory(session, fixed)
    session.refresh(f)
    assert f.status == "resolved" and scan.summary["resolved"] == 1


def test_run_persistence_records_every_layer(session):
    result = run_scenario(SCENARIOS["indirect-injection"], SimulatorProvider("naive"), "protected")
    run = persist_run(session, result)
    assert run.is_simulated and run.provider == "simulator" and run.outcome == "failed"
    assert count(session, ModelInteraction) == len(result.trace.interactions)
    assert count(session, ToolCallAttempt) == 3
    assert count(session, AuthorizationDecision) == 3
    assert count(session, EvidenceEvent) == len(result.trace.events)
    denied = session.scalars(select(AuthorizationDecision).where(AuthorizationDecision.decision == "deny")).all()
    assert sorted(r for d in denied for r in d.rule_ids) == ["GW-004", "GW-005"]


def test_reevaluation_from_stored_evidence_matches(session):
    for mode in ("vulnerable", "protected"):
        result = run_scenario(SCENARIOS["tool-output-injection"], SimulatorProvider("naive"), mode)
        run = persist_run(session, result)
        session.flush()
        from agentshield.redteam.evaluator import evaluate

        again = evaluate(SCENARIOS["tool-output-injection"], trace_from_run(run))
        assert again["outcome"] == result.evaluation["outcome"]
        assert again["checks"] == result.evaluation["checks"]


def test_secrets_are_redacted_before_storage(session):
    result = run_scenario(SCENARIOS["direct-injection"], SimulatorProvider("naive"), "vulnerable")
    result.trace.final_answer += " leaked AKIAIOSFODNN7EXAMPLE"
    run = persist_run(session, result)
    assert "AKIAIOSFODNN7EXAMPLE" not in run.final_answer


def test_demo_and_correlations(session):
    out = run_demo(session)
    assert len(out["runs"]) == 9
    assert count(session, TestRun) == 9
    rows = {c.rule_id: c for c in session.scalars(select(RiskCorrelation)).all()}
    assert set(rows) == {"CORR-001", "CORR-002", "CORR-003"}
    assert rows["CORR-001"].status == "agent_step_observed_in_simulation"
    assert rows["CORR-001"].finding_ids and rows["CORR-001"].run_ids
    assert rows["CORR-002"].status == "modeled"  # public READ only: not an injection entry point
    assert rows["CORR-002"].evidence["public_write"] is False
    for c in rows.values():
        assert c.status in ("modeled", "agent_step_observed_in_simulation")
        assert c.path["nodes"] and c.path["edges"]
    # Recomputing is idempotent.
    compute_correlations(session)
    assert count(session, RiskCorrelation) == 3


def test_upgrade_creates_missing_sqlite_directory(tmp_path):
    from agentshield.db import upgrade_database

    target = tmp_path / "nested" / "dir" / "fresh.db"
    upgrade_database(f"sqlite:///{target.as_posix()}")
    assert target.is_file()
