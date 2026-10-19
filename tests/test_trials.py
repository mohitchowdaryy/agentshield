"""Repeated trial sets: stored counts, run linkage, API, CLI and migration round-trip."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from typer.testing import CliRunner

from agentshield.agent.providers.base import ModelProvider, ModelRequest, ModelResponse, ProviderError
from agentshield.cli import app as cli_app
from agentshield.models import TestRun, TrialSet
from agentshield.redteam.scenarios import SCENARIOS
from agentshield.services.trials import MAX_TRIALS, run_trials, summarize


class FlakyProvider(ModelProvider):
    """Answers on odd calls, raises a provider error on even calls, to give mixed outcomes."""

    name, model, is_simulated = "flaky", "flaky-test-model", True

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        if self.calls % 2 == 0:
            raise ProviderError("simulated timeout")
        return ModelResponse(text="Done.", model=self.model)


SCENARIO = SCENARIOS["direct-injection"]


def test_run_trials_stores_counts_and_links_runs(session):
    ts = run_trials(session, SCENARIO, FlakyProvider(), "protected", 4)
    assert ts.trials == 4 and ts.provider == "flaky" and ts.is_simulated
    assert ts.outcome_counts == {"succeeded": 0, "failed": 2, "inconclusive": 0, "errored": 2}
    assert sum(ts.outcome_counts.values()) == 4
    assert ts.check_counts["simulated_violation_executed"] == 0
    runs = session.scalars(select(TestRun).where(TestRun.trial_set_fk == ts.id).order_by(TestRun.trial_index)).all()
    assert [r.trial_index for r in runs] == [1, 2, 3, 4]
    assert [r.id for r in runs] == ts.run_ids
    assert all(r.batch_id == ts.id for r in runs)
    assert ts.finished_at is not None


@pytest.mark.parametrize("n", [0, MAX_TRIALS + 1])
def test_trial_count_bounds(session, n):
    with pytest.raises(ValueError):
        run_trials(session, SCENARIO, FlakyProvider(), "protected", n)


def test_summarize_counts_true_checks_and_sums_integers():
    class R:
        def __init__(self, outcome, checks):
            self.outcome, self.evaluation = outcome, {"checks": checks}

    outcomes, checks = summarize(
        [
            R(
                "failed",
                {"legitimate_task_completed": True, "unsafe_calls_denied_by_gateway": 2, "run_status": "completed"},
            ),
            R("failed", {"legitimate_task_completed": False, "unsafe_calls_denied_by_gateway": 1}),
            R(None, {}),
        ]
    )
    assert outcomes["failed"] == 2 and outcomes["errored"] == 1
    assert checks == {"legitimate_task_completed": 1, "unsafe_calls_denied_by_gateway": 3}


def test_trial_set_persists_across_sessions(db_url):
    from agentshield.db import session_scope

    with session_scope(db_url) as s:
        ts_id = run_trials(s, SCENARIO, FlakyProvider(), "vulnerable", 2).id
    with session_scope(db_url) as s:
        ts = s.get(TrialSet, ts_id)
        assert ts is not None and ts.policy_mode == "vulnerable" and len(ts.run_ids) == 2


@pytest.fixture()
def client(db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_STATIC_DIR", str(tmp_path / "no-dist"))
    from agentshield.api.app import create_app
    from agentshield.config import get_settings

    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c


def test_api_create_and_list_trials(client):
    r = client.post("/api/redteam/trials", json={"scenario_id": SCENARIO.id, "trials": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["trials"] == 3 and sum(body["outcome_counts"].values()) == 3
    assert body["is_simulated"] is True
    listed = client.get("/api/redteam/trials").json()
    assert [t["id"] for t in listed] == [body["id"]]
    assert client.get("/api/redteam/trials", params={"scenario": "other"}).json() == []
    run = client.get(f"/api/redteam/runs/{body['run_ids'][0]}").json()
    assert run["trial_set_id"] == body["id"] and run["trial_index"] == 1


@pytest.mark.parametrize(
    "payload,status",
    [
        ({"scenario_id": SCENARIO.id, "trials": 0}, 422),
        ({"scenario_id": SCENARIO.id, "trials": 51}, 422),
        ({"scenario_id": "unknown", "trials": 2}, 404),
        ({"scenario_id": SCENARIO.id, "trials": 2, "provider": "bogus"}, 400),
    ],
)
def test_api_trial_validation(client, payload, status):
    assert client.post("/api/redteam/trials", json=payload).status_code == status


runner = CliRunner()


def test_cli_trials(db_url):
    r = runner.invoke(cli_app, ["redteam", "run", "--scenario", SCENARIO.id, "--trials", "2"])
    assert r.exit_code == 0, r.output
    out = " ".join(r.output.split())  # Rich wraps lines at the terminal width
    assert "2 trials" in out and "not a rate" in out
    r = runner.invoke(cli_app, ["redteam", "run", "--scenario", SCENARIO.id, "--trials", "0"])
    assert r.exit_code == 2


def test_migration_downgrade_and_upgrade(tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, inspect

    from agentshield.db import alembic_config, upgrade_database

    url = f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"
    upgrade_database(url)
    command.downgrade(alembic_config(url), "0001")
    engine = create_engine(url)
    assert "trial_sets" not in inspect(engine).get_table_names()
    engine.dispose()
    upgrade_database(url)
    engine = create_engine(url)
    insp = inspect(engine)
    assert "trial_sets" in insp.get_table_names()
    assert {"trial_set_fk", "trial_index"} <= {c["name"] for c in insp.get_columns("test_runs")}
    engine.dispose()
