import json

from typer.testing import CliRunner

from agentshield.cli import app

runner = CliRunner()


def test_help_lists_commands():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    for cmd in ("doctor", "demo", "scan", "redteam", "evaluate", "report", "serve"):
        assert cmd in r.output


def test_redteam_list(db_url):
    r = runner.invoke(app, ["redteam", "list"])
    assert r.exit_code == 0 and "indirect" in r.output


def test_doctor(db_url):
    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 0, r.output


def test_run_evaluate_and_report(db_url, tmp_path):
    r = runner.invoke(app, ["redteam", "run", "--scenario", "indirect-injection", "--mode", "protected"])
    assert r.exit_code == 0, r.output
    out = tmp_path / "report.json"
    r = runner.invoke(app, ["report", "--format", "json", "--kind", "runs", "--output", str(out)])
    assert r.exit_code == 0
    data = json.loads(out.read_text())
    run_id = data["runs"][0]["id"]
    r = runner.invoke(app, ["evaluate", "--run-id", run_id, "--json"])
    assert r.exit_code == 0
    assert '"outcome": "failed"' in r.output


def test_demo_and_csv_report(db_url):
    assert runner.invoke(app, ["demo"]).exit_code == 0
    r = runner.invoke(app, ["report", "--format", "csv", "--kind", "findings"])
    assert r.exit_code == 0 and r.output.startswith("id,rule_id")


def test_errors_are_clear(db_url):
    r = runner.invoke(app, ["redteam", "run", "--scenario", "nope"])
    assert r.exit_code == 2 and "unknown scenario" in r.output
    r = runner.invoke(app, ["redteam", "run", "--scenario", "direct-injection", "--mode", "off"])
    assert r.exit_code == 2
    r = runner.invoke(app, ["evaluate", "--run-id", "run_missing"])
    assert r.exit_code == 2
    r = runner.invoke(app, ["report", "--format", "csv", "--kind", "all"])
    assert r.exit_code == 2


def test_scan_aws_without_credentials_fails_cleanly(db_url, monkeypatch):
    from agentshield.cloud import aws

    def fail(self):
        raise aws.AwsScanError("No AWS credentials found.")

    monkeypatch.setattr(aws.AwsCollector, "collect", fail)
    r = runner.invoke(app, ["scan", "aws", "--region", "us-east-1"])
    assert r.exit_code == 2 and "AWS scan failed" in r.output
