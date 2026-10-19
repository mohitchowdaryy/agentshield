import csv
import io

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_STATIC_DIR", str(tmp_path / "no-dist"))
    from agentshield.api.app import create_app
    from agentshield.config import get_settings

    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/api/health").json()["database"] == "ok"


def test_empty_state(client):
    o = client.get("/api/overview").json()
    assert o["findings"]["open"] == 0 and o["redteam"]["runs"] == 0
    assert client.get("/api/findings").json() == []


def test_demo_then_queries(client):
    r = client.post("/api/demo")
    assert r.status_code == 200
    o = client.get("/api/overview").json()
    assert o["findings"]["open"] == 13
    assert o["redteam"]["runs"] == 9 and o["redteam"]["simulated_runs"] == 9
    assert o["gateway"]["denied"] > 0

    crit = client.get("/api/findings", params={"severity": "critical"}).json()
    assert crit and all(f["severity"] == "critical" for f in crit)
    search = client.get("/api/findings", params={"q": "legacy-ci"}).json()
    assert search and all("legacy-ci" in f["resource_arn"] for f in search)
    detail = client.get(f"/api/findings/{crit[0]['id']}").json()
    assert detail["evidence"] and detail["observations"]

    runs = client.get("/api/redteam/runs", params={"mode": "protected"}).json()
    assert len(runs) == 6 and all(r["policy_mode"] == "protected" for r in runs)
    run = client.get(f"/api/redteam/runs/{runs[0]['id']}").json()
    assert run["tool_calls"] and run["events"] and run["interactions"]
    assert all(tc["decision"] for tc in run["tool_calls"])

    denied = client.get("/api/tool-calls", params={"decision": "deny"}).json()
    assert denied and all(t["decision"] == "deny" for t in denied)
    corr = client.get("/api/correlations").json()
    assert {c["rule_id"] for c in corr} == {"CORR-001", "CORR-002", "CORR-003"}


def test_exports(client):
    client.post("/api/demo")
    rows = list(csv.DictReader(io.StringIO(client.get("/api/findings/export", params={"format": "csv"}).text)))
    assert len(rows) == 13 and "fingerprint" in rows[0]
    js = client.get("/api/findings/export", params={"format": "json"}).json()
    assert len(js) == 13 and "evidence" in js[0]
    runs_csv = client.get("/api/redteam/runs/export", params={"format": "csv"}).text
    assert runs_csv.startswith("id,scenario_id")


def test_create_run_and_validation(client):
    r = client.post("/api/redteam/runs", json={"scenario_id": "direct-injection", "mode": "protected"})
    assert r.status_code == 200 and r.json()["outcome"] == "failed"
    assert client.post("/api/redteam/runs", json={"scenario_id": "nope"}).status_code == 404
    assert client.post("/api/redteam/runs", json={"scenario_id": "direct-injection", "mode": "off"}).status_code == 422
    assert (
        client.post("/api/redteam/runs", json={"scenario_id": "direct-injection", "provider": "bogus"}).status_code
        == 400
    )


def test_body_size_limit(client):
    big = "x" * 300_000
    r = client.post("/api/redteam/runs", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_scan_request_validation(client):
    assert client.post("/api/scans", json={"source": "gcp"}).status_code == 422
    assert client.post("/api/scans", json={"source": "aws", "profile": "bad profile;rm"}).status_code == 422
    r = client.post("/api/scans", json={"source": "demo"})
    assert r.status_code == 200 and r.json()["source"] == "demo"


def test_cors_restricted(client):
    ok = client.options(
        "/api/overview", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"}
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options(
        "/api/overview", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"}
    )
    assert "access-control-allow-origin" not in bad.headers


def test_api_token_enforced_on_mutations(db_url, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_API_TOKEN", "s3cret-token-value")
    monkeypatch.setenv("AGENTSHIELD_STATIC_DIR", str(tmp_path / "no-dist"))
    from agentshield.api.app import create_app
    from agentshield.config import get_settings

    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        assert c.post("/api/demo").status_code == 401
        assert c.get("/api/overview").status_code == 200
        assert c.post("/api/demo", headers={"Authorization": "Bearer s3cret-token-value"}).status_code == 200
        settings = c.get("/api/settings").json()
        assert settings["api_token_required"] is True
        assert "s3cret" not in str(settings)
