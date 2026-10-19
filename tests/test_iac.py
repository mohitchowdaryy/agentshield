"""Infrastructure-as-Code scanning: Checkov runner, parser, persistence, comparison, API and CLI.

Unit tests replay real captured Checkov output through a fake executable. The real scanner runs in
`test_real_checkov_lab_demo` (skipped when Checkov is not installed).
"""

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agentshield.iac import checkov as ck
from agentshield.iac.checkov import CheckovError, parse_report, scan_directory

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "checkov"
FAKE = [sys.executable, str(FIXTURES / "fake_checkov.py")]
LAB = ROOT / "terraform-lab"

TARGETED_CHECKS = {
    "CKV_AWS_53",
    "CKV_AWS_54",
    "CKV_AWS_55",
    "CKV_AWS_56",
    "CKV_AWS_70",  # public storage
    "CKV_AWS_24",
    "CKV_AWS_25",
    "CKV_AWS_382",  # open security group
    "CKV_AWS_62",
    "CKV_AWS_63",
    "CKV2_AWS_40",  # broad IAM
}


def load(name: str):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture()
def lab_env(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_IAC_LAB_DIR", str(LAB))
    from agentshield.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture()
def fake_scanner(monkeypatch, lab_env):
    monkeypatch.setattr("agentshield.services.iac.find_checkov", lambda configured=None: list(FAKE))
    monkeypatch.delenv("FAKE_CHECKOV_MODE", raising=False)
    return FAKE


# -- parser (real Checkov output) ---------------------------------------------------------------


def test_parse_real_insecure_output():
    results, summary, errors = parse_report(load("insecure"))
    assert summary == {"passed": 15, "failed": 25, "skipped": 0, "parsing_errors": 0, "resource_count": 7}
    assert errors == []
    failed = [r for r in results if r.result == "failed"]
    assert len(failed) == 25 and sum(r.result == "passed" for r in results) == 15
    assert TARGETED_CHECKS <= {r.check_id for r in failed}
    ssh = next(r for r in failed if r.check_id == "CKV_AWS_24")
    assert ssh.resource == "aws_security_group.app" and ssh.resource_type == "aws_security_group"
    assert ssh.file_path == "main.tf" and ssh.line_start and ssh.line_end and ssh.line_start <= ssh.line_end
    assert ssh.evidence["code"] and "evaluated_keys" in ssh.evidence
    assert ssh.check_name in ssh.remediation


def test_severity_is_never_invented():
    results, _, _ = parse_report(load("insecure"))
    raw = [c for c in load("insecure")["results"]["failed_checks"]]
    assert all(c["severity"] is None for c in raw)  # what Checkov actually reported
    assert all(r.severity is None for r in results)
    assert all(r.guideline is None for r in results)


def test_parser_keeps_reported_severity_and_handles_shapes():
    data = load("secure")
    data["results"]["failed_checks"][0]["severity"] = "HIGH"
    results, summary, _ = parse_report(
        [
            data,
            {
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "parsing_errors": 0,
                "resource_count": 0,
                "checkov_version": "3.3.29",
            },
        ]
    )
    assert results[0].severity == "HIGH"
    assert summary["failed"] == 4 and summary["passed"] == 41
    with pytest.raises(CheckovError):
        parse_report({"unexpected": True})
    with pytest.raises(CheckovError):
        parse_report(["not an object"])


def test_fingerprint_is_stable_and_specific():
    a, _, _ = parse_report(load("insecure"))
    b, _, _ = parse_report(load("insecure"))
    assert [x.fingerprint for x in a] == [x.fingerprint for x in b]
    assert len({(x.check_id, x.resource) for x in a}) == len({x.fingerprint for x in a})


# -- subprocess runner -----------------------------------------------------------------------------


def test_scan_directory_argument_handling(tmp_path, monkeypatch):
    target = tmp_path / "dir with spaces; rm -rf" / "insecure"
    target.mkdir(parents=True)
    record = tmp_path / "args.jsonl"
    monkeypatch.setenv("FAKE_CHECKOV_ARGS_FILE", str(record))
    report = scan_directory(target, FAKE, timeout=60)
    calls = [json.loads(line) for line in record.read_text().splitlines()]
    scan_args = calls[-1]
    assert scan_args[scan_args.index("--directory") + 1] == str(target.resolve())  # one argument, unchanged
    assert {"--soft-fail", "--skip-download", "--output", "json"} <= set(scan_args)
    assert report.scanner_version == "3.3.29" and report.summary["failed"] == 25
    assert "<target>" in report.command and str(target) not in " ".join(report.command)


@pytest.mark.parametrize(
    "mode,match",
    [
        ("fail", "exited with 2"),
        ("badjson", "not valid JSON"),
        ("noversion", "--version"),
    ],
)
def test_scan_directory_errors(tmp_path, monkeypatch, mode, match):
    monkeypatch.setenv("FAKE_CHECKOV_MODE", mode)
    with pytest.raises(CheckovError, match=match):
        scan_directory(tmp_path, FAKE, timeout=60)


def test_scan_directory_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_CHECKOV_MODE", "sleep")
    monkeypatch.setattr(ck, "checkov_version", lambda command, timeout=60.0: "3.3.29")
    with pytest.raises(CheckovError, match="timed out"):
        scan_directory(tmp_path, FAKE, timeout=1)


def test_scan_directory_rejects_non_directory(tmp_path):
    with pytest.raises(CheckovError, match="not a directory"):
        scan_directory(tmp_path / "missing", FAKE)


def test_find_checkov_resolution(tmp_path, monkeypatch):
    with pytest.raises(CheckovError, match="does not exist"):
        ck.find_checkov(str(tmp_path / "nope"))
    py = tmp_path / "python.exe"
    py.write_text("")
    assert ck.find_checkov(str(py)) == [str(py.resolve()), "-m", "checkov.main"]
    cmd = tmp_path / "checkov.cmd"
    cmd.write_text("")
    assert ck.find_checkov(str(cmd))[1:] == ["-m", "checkov.main"]  # never run through cmd.exe
    lonely = tmp_path / "solo" / "checkov.bat"
    lonely.parent.mkdir()
    lonely.write_text("")
    with pytest.raises(CheckovError, match="without a shell"):
        ck.find_checkov(str(lonely))
    monkeypatch.setattr(ck.shutil, "which", lambda name: None)
    monkeypatch.setattr(ck.Path, "home", staticmethod(lambda: tmp_path / "empty-home"))
    with pytest.raises(CheckovError, match="not found"):
        ck.find_checkov(None)


# -- persistence and comparison --------------------------------------------------------------------


def test_lab_demo_persists_and_compares(session, fake_scanner):
    from agentshield.models import IacFinding, IacScan
    from agentshield.services.iac import run_lab_demo

    result = run_lab_demo(session)
    c = result["counts"]
    assert c == {
        "failed_before": 25,
        "failed_after": 4,
        "fixed": 21,
        "still_failing": 4,
        "new_failures": 0,
        "not_evaluated_after": 0,
    }
    assert TARGETED_CHECKS <= {f["check_id"] for f in result["fixed"]}
    assert result["before"]["kind"] == "iac_static_analysis"
    assert session.query(IacScan).count() == 2
    assert session.query(IacFinding).count() == 40 + 45
    stored = session.query(IacFinding).filter_by(check_id="CKV_AWS_24", result="failed").one()
    assert stored.severity is None and stored.file_path == "main.tf" and stored.evidence["code"]


def test_compare_reports_new_failures_and_unevaluated(session, fake_scanner):
    from agentshield.iac.checkov import CheckovReport
    from agentshield.services.iac import compare_scans, persist_report

    results, summary, _ = parse_report(load("insecure"))
    before = persist_report(session, CheckovReport("3.3.29", "x", results, summary, [], []), "before", LAB, 1.0)
    changed = []
    for r in results:
        if r.check_id == "CKV_AWS_24":
            continue  # resource no longer evaluated by this check
        if r.check_id == "CKV_AWS_53":
            r.result = "passed"
        if r.result == "passed" and r.check_id != "CKV_AWS_53":
            r.result = "failed"  # previously passing checks now fail
        changed.append(r)
    after = persist_report(session, CheckovReport("3.3.29", "x", changed, summary, [], []), "after", LAB, 1.0)
    cmp = compare_scans(session, before.id, after.id)
    assert [f["check_id"] for f in cmp["fixed"]] == ["CKV_AWS_53"]
    assert [f["check_id"] for f in cmp["not_evaluated_after"]] == ["CKV_AWS_24"]
    assert cmp["counts"]["new_failures"] == 15
    with pytest.raises(KeyError):
        compare_scans(session, before.id, "missing")


def test_failed_scan_is_recorded_not_lost(db_url, fake_scanner, monkeypatch):
    from agentshield.db import session_scope
    from agentshield.models import IacScan
    from agentshield.services.iac import lab_target, run_iac_scan

    monkeypatch.setenv("FAKE_CHECKOV_MODE", "fail")
    with session_scope(db_url) as s:
        scan = run_iac_scan(s, lab_target("insecure"), "insecure")
        assert scan.status == "failed" and "exited with 2" in scan.error
    with session_scope(db_url) as s:
        assert s.query(IacScan).filter_by(status="failed").count() == 1


def test_lab_target_validation(lab_env):
    from agentshield.services.iac import lab_target

    with pytest.raises(ValueError):
        lab_target("../../etc")
    assert lab_target("secure") == (LAB / "secure").resolve()


# -- API --------------------------------------------------------------------------------------------


@pytest.fixture()
def client(db_url, tmp_path, monkeypatch, fake_scanner):
    monkeypatch.setenv("AGENTSHIELD_STATIC_DIR", str(tmp_path / "no-dist"))
    from agentshield.api.app import create_app
    from agentshield.config import get_settings

    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c


def test_api_iac_flow(client):
    assert client.get("/api/iac/compare").status_code == 404  # nothing scanned yet
    demo = client.post("/api/iac/demo")
    assert demo.status_code == 200 and demo.json()["counts"]["fixed"] == 21
    scans = client.get("/api/iac/scans").json()
    assert [s["label"] for s in scans] == ["secure", "insecure"]
    insecure_id = scans[1]["id"]
    failed = client.get("/api/iac/findings", params={"scan_id": insecure_id, "result": "failed"}).json()
    assert len(failed) == 25 and all(f["severity"] is None for f in failed)
    sg = client.get(
        "/api/iac/findings", params={"scan_id": insecure_id, "resource": "aws_security_group.app", "result": "failed"}
    ).json()
    assert {f["check_id"] for f in sg} >= {"CKV_AWS_24", "CKV_AWS_25"}
    assert all(f["resource"] == "aws_security_group.app" for f in sg)
    cmp = client.get("/api/iac/compare").json()
    assert cmp["counts"]["failed_before"] == 25 and cmp["counts"]["failed_after"] == 4
    csv_text = client.get("/api/iac/findings/export", params={"format": "csv", "scan_id": insecure_id}).text
    assert csv_text.startswith("scan_id,check_id") and csv_text.count("\n") == 41


def test_api_iac_validation(client, monkeypatch):
    assert client.post("/api/iac/scans", json={"target": "/etc"}).status_code == 422
    assert client.get("/api/iac/scans/missing").status_code == 404
    assert client.get("/api/iac/findings", params={"result": "bogus"}).status_code == 422
    monkeypatch.setenv("FAKE_CHECKOV_MODE", "fail")
    assert client.post("/api/iac/demo").status_code == 503
    r = client.post("/api/iac/scans", json={"target": "insecure"})
    assert r.status_code == 200 and r.json()["status"] == "failed"


def test_api_scanner_unavailable(client, monkeypatch):
    def missing(configured=None):
        raise CheckovError("Checkov not found.")

    monkeypatch.setattr("agentshield.services.iac.find_checkov", missing)
    info = client.get("/api/iac/scanner").json()
    assert info["available"] is False and "not found" in info["error"]


# -- CLI --------------------------------------------------------------------------------------------

runner = CliRunner()


def test_cli_iac_demo_and_scan(db_url, fake_scanner):
    from agentshield.cli import app

    r = runner.invoke(app, ["iac", "demo"])
    assert r.exit_code == 0, r.output
    out = " ".join(r.output.split())
    assert "fixed 21" in out and "new failures 0" in out and "static analysis" in out
    r = runner.invoke(app, ["iac", "scan", str(LAB / "insecure"), "--label", "insecure"])
    assert r.exit_code == 0, r.output
    assert "CKV_AWS_24" in r.output and "not provided" in r.output
    assert runner.invoke(app, ["iac", "scan", str(LAB / "missing")]).exit_code == 2
    assert runner.invoke(app, ["iac", "compare", "--before", "x", "--after", "y"]).exit_code == 2


def test_cli_iac_scan_failure(db_url, fake_scanner, monkeypatch):
    from agentshield.cli import app

    monkeypatch.setenv("FAKE_CHECKOV_MODE", "fail")
    r = runner.invoke(app, ["iac", "scan", str(LAB / "insecure")])
    assert r.exit_code == 2 and "Checkov scan failed" in r.output


# -- migration -------------------------------------------------------------------------------------


def test_migration_0003_round_trip(tmp_path):
    from alembic import command
    from sqlalchemy import create_engine, inspect

    from agentshield.db import alembic_config, upgrade_database

    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    upgrade_database(url)
    command.downgrade(alembic_config(url), "0002")
    engine = create_engine(url)
    assert "iac_scans" not in inspect(engine).get_table_names()
    engine.dispose()
    upgrade_database(url)
    engine = create_engine(url)
    assert {"iac_scans", "iac_findings"} <= set(inspect(engine).get_table_names())
    engine.dispose()


# -- real scanner (integration) ---------------------------------------------------------------------


def _real_checkov():
    try:
        return ck.find_checkov(None)
    except CheckovError:
        return None


@pytest.mark.skipif(_real_checkov() is None, reason="Checkov is not installed")
def test_real_checkov_lab_demo(session, lab_env):
    from agentshield.services.iac import run_lab_demo

    result = run_lab_demo(session)
    assert "error" not in result, result.get("error")
    c = result["counts"]
    assert c["failed_before"] > c["failed_after"]
    assert c["new_failures"] == 0
    assert TARGETED_CHECKS <= {f["check_id"] for f in result["fixed"]}
    assert result["before"]["scanner_version"]
