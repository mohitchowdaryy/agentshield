"""FastAPI application. Security logic lives in the services; this module only validates and routes."""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session, selectinload, sessionmaker

from agentshield import __version__
from agentshield.agent.providers import ProviderError, get_provider
from agentshield.config import Settings, get_settings
from agentshield.correlation.engine import compute_correlations
from agentshield.db import get_engine, upgrade_database
from agentshield.models import (
    Agent,
    Finding,
    FindingObservation,
    Resource,
    RiskCorrelation,
    Scan,
    TestRun,
    TestScenario,
    ToolCallAttempt,
)
from agentshield.redteam.engine import run_scenario
from agentshield.redteam.scenarios import SCENARIOS
from agentshield.services import queries as q
from agentshield.services.demo import run_demo
from agentshield.services.redteam import persist_run, sync_agents, sync_scenarios
from agentshield.services.scans import run_scan

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ScanRequest(BaseModel):
    source: Literal["demo", "aws"] = "demo"
    profile: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")
    regions: list[str] = Field(default_factory=list, max_length=30)


class RunRequest(BaseModel):
    scenario_id: str = Field(max_length=64)
    mode: Literal["protected", "vulnerable"] = "protected"
    provider: str = Field(default="simulator", max_length=32)
    profile: Literal["naive", "resistant"] = "naive"


class TrialRequest(BaseModel):
    scenario_id: str = Field(max_length=64)
    mode: Literal["protected", "vulnerable"] = "protected"
    provider: str = Field(default="simulator", max_length=32)
    profile: Literal["naive", "resistant"] = "naive"
    trials: int = Field(default=5, ge=1, le=50)


PolicyModeName = Literal["protected", "vulnerable"]


def _default_modes() -> list[PolicyModeName]:
    return ["vulnerable", "protected"]


class RunAllRequest(BaseModel):
    modes: list[PolicyModeName] = Field(default_factory=_default_modes)
    provider: str = Field(default="simulator", max_length=32)
    profile: Literal["naive", "resistant"] = "naive"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    upgrade_database(settings.database_url)
    factory = sessionmaker(bind=get_engine(settings.database_url), expire_on_commit=False)
    with factory() as s:
        sync_agents(s)
        sync_scenarios(s)
        s.commit()

    app = FastAPI(title="AgentShield API", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def limits_and_headers(request: Request, call_next: Any) -> Response:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_request_bytes:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        if request.method == "POST" and not length and request.headers.get("transfer-encoding"):
            return JSONResponse({"detail": "chunked request bodies are not accepted"}, status_code=411)
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def session() -> Iterator[Session]:
        s = factory()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def require_token(request: Request) -> None:
        token = settings.api_token.get_secret_value() if settings.api_token else None
        if not token:
            return
        header = request.headers.get("authorization", "")
        if not secrets.compare_digest(header, f"Bearer {token}"):
            raise HTTPException(status_code=401, detail="missing or invalid API token")

    # -- health ------------------------------------------------------------------------------
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/health")
    def api_health(s: Session = Depends(session)) -> dict[str, Any]:
        s.execute(text("SELECT 1"))
        return {"status": "ok", "version": __version__, "database": "ok"}

    # -- overview / settings -----------------------------------------------------------------
    @app.get("/api/overview")
    def overview(s: Session = Depends(session)) -> dict[str, Any]:
        return q.overview(s)

    @app.get("/api/settings")
    def settings_view() -> dict[str, Any]:
        return {
            "version": __version__,
            "database": settings.database_url.split("://")[0],
            "bind": f"{settings.host}:{settings.port}",
            "cors_origins": settings.cors_origins,
            "api_token_required": settings.api_token is not None,
            "max_request_bytes": settings.max_request_bytes,
            "agent": {
                "max_turns": settings.max_agent_turns,
                "timeout_s": settings.model_timeout_seconds,
                "max_retries": settings.model_max_retries,
            },
            "integrations": {
                "simulator": {"available": True, "note": "Deterministic offline simulation"},
                "anthropic": {
                    "configured": bool(os.environ.get("ANTHROPIC_API_KEY")),
                    "model": settings.anthropic_model,
                },
                "ollama": {
                    "base_url": settings.ollama_base_url,
                    "model": settings.ollama_model,
                    "note": "Local open-weight model; free, no API key",
                },
                "aws": {
                    "profile": settings.aws_profile or os.environ.get("AWS_PROFILE"),
                    "regions": settings.aws_regions,
                    "note": "Credentials resolved by the standard AWS chain at scan time; never stored.",
                },
            },
        }

    # -- cloud -------------------------------------------------------------------------------
    @app.get("/api/scans")
    def list_scans(s: Session = Depends(session)) -> list[dict[str, Any]]:
        rows = s.scalars(select(Scan).options(selectinload(Scan.account)).order_by(Scan.started_at.desc())).all()
        return [q.scan_dict(r) for r in rows]

    @app.post("/api/scans", dependencies=[Depends(require_token)])
    def create_scan(req: ScanRequest, s: Session = Depends(session)) -> dict[str, Any]:
        if req.source == "demo":
            from agentshield.cloud.demo import DemoCollector

            collector: Any = DemoCollector()
        else:
            from agentshield.cloud.aws import AwsCollector, AwsScanError

            try:
                collector = AwsCollector(
                    profile=req.profile or settings.aws_profile, regions=req.regions or settings.aws_regions
                )
                scan = run_scan(s, collector)
            except AwsScanError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            compute_correlations(s)
            return q.scan_dict(scan)
        scan = run_scan(s, collector)
        compute_correlations(s)
        return q.scan_dict(scan)

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        row = s.get(Scan, scan_id)
        if row is None:
            raise HTTPException(404, "scan not found")
        d = q.scan_dict(row)
        obs = s.scalars(
            select(Finding)
            .join(FindingObservation, FindingObservation.finding_fk == Finding.id)
            .where(FindingObservation.scan_fk == scan_id)
        ).all()
        d["findings"] = [q.finding_dict(f) for f in obs]
        return d

    def _filtered_findings(
        s: Session,
        severity: list[str] | None,
        status: str | None,
        source: str | None,
        rule_id: str | None,
        search: str | None,
        sort: str,
        order: str,
    ) -> list[Finding]:
        stmt = select(Finding)
        if severity:
            stmt = stmt.where(Finding.severity.in_(severity))
        if status:
            stmt = stmt.where(Finding.status == status)
        if source:
            stmt = stmt.where(Finding.source == source)
        if rule_id:
            stmt = stmt.where(Finding.rule_id == rule_id)
        if search:
            like = f"%{search.lower()}%"
            stmt = stmt.where(
                Finding.title.ilike(like) | Finding.resource_arn.ilike(like) | Finding.rule_id.ilike(like)
            )
        rows = list(s.scalars(stmt).all())
        keyfn: Any = {
            "severity": lambda f: SEVERITY_RANK.get(f.severity, 9),
            "last_seen": lambda f: f.last_seen_at,
            "first_seen": lambda f: f.first_seen_at,
            "rule_id": lambda f: f.rule_id,
            "resource": lambda f: f.resource_arn,
        }.get(sort, lambda f: SEVERITY_RANK.get(f.severity, 9))
        rows.sort(key=keyfn, reverse=(order == "desc"))
        return rows

    @app.get("/api/findings")
    def list_findings(
        severity: list[str] | None = Query(default=None),
        status: str | None = Query(default=None, max_length=16),
        source: str | None = Query(default=None, max_length=16),
        rule_id: str | None = Query(default=None, max_length=32),
        q_: str | None = Query(default=None, alias="q", max_length=200),
        sort: str = Query(default="severity", max_length=16),
        order: Literal["asc", "desc"] = "asc",
        s: Session = Depends(session),
    ) -> list[dict[str, Any]]:
        rows = _filtered_findings(s, severity, status, source, rule_id, q_, sort, order)
        return [q.finding_dict(f) for f in rows]

    @app.get("/api/findings/export")
    def export_findings(
        format: Literal["json", "csv"] = "json",
        severity: list[str] | None = Query(default=None),
        status: str | None = Query(default=None, max_length=16),
        source: str | None = Query(default=None, max_length=16),
        s: Session = Depends(session),
    ) -> Response:
        rows = [
            q.finding_dict(f, detail=True)
            for f in _filtered_findings(s, severity, status, source, None, None, "severity", "asc")
        ]
        if format == "csv":
            return PlainTextResponse(
                q.to_csv(rows, q.FINDING_CSV_FIELDS),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=agentshield-findings.csv"},
            )
        return JSONResponse(rows, headers={"Content-Disposition": "attachment; filename=agentshield-findings.json"})

    @app.get("/api/findings/{finding_id}")
    def get_finding(finding_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        d = q.finding_dict(f, detail=True)
        d["observations"] = [
            {"scan_id": o.scan_fk, "observed_at": q._iso(o.observed_at)}
            for o in s.scalars(
                select(FindingObservation)
                .where(FindingObservation.finding_fk == f.id)
                .order_by(FindingObservation.observed_at.desc())
            ).all()
        ]
        d["correlations"] = [c.id for c in s.scalars(select(RiskCorrelation)).all() if f.id in c.finding_ids]
        return d

    @app.get("/api/resources")
    def list_resources(s: Session = Depends(session)) -> list[dict[str, Any]]:
        return [
            {
                "id": r.id,
                "arn": r.arn,
                "type": r.resource_type,
                "name": r.name,
                "region": r.region,
                "last_seen_at": q._iso(r.last_seen_at),
            }
            for r in s.scalars(select(Resource).order_by(Resource.resource_type, Resource.name)).all()
        ]

    # -- agents / red team ---------------------------------------------------------------------
    @app.get("/api/agents")
    def list_agents(s: Session = Depends(session)) -> list[dict[str, Any]]:
        return [q.agent_dict(a) for a in s.scalars(select(Agent)).all()]

    @app.get("/api/redteam/scenarios")
    def list_scenarios(s: Session = Depends(session)) -> list[dict[str, Any]]:
        return [q.scenario_dict(x) for x in s.scalars(select(TestScenario).order_by(TestScenario.id)).all()]

    def _run(
        s: Session, scenario_id: str, mode: str, provider_name: str, profile: str, batch_id: str | None = None
    ) -> TestRun:
        if scenario_id not in SCENARIOS:
            raise HTTPException(404, f"unknown scenario '{scenario_id}'")
        try:
            provider = get_provider(provider_name, profile)
        except ProviderError as exc:
            raise HTTPException(400, str(exc)) from exc
        result = run_scenario(SCENARIOS[scenario_id], provider, mode)  # type: ignore[arg-type]
        return persist_run(s, result, batch_id)

    @app.post("/api/redteam/runs", dependencies=[Depends(require_token)])
    def create_run(req: RunRequest, s: Session = Depends(session)) -> dict[str, Any]:
        run = _run(s, req.scenario_id, req.mode, req.provider, req.profile)
        compute_correlations(s)
        s.flush()
        s.refresh(run)
        return q.run_detail(run)

    @app.post("/api/redteam/trials", dependencies=[Depends(require_token)])
    def create_trials(req: TrialRequest, s: Session = Depends(session)) -> dict[str, Any]:
        from agentshield.services.trials import run_trials, trial_set_dict

        if req.scenario_id not in SCENARIOS:
            raise HTTPException(404, f"unknown scenario '{req.scenario_id}'")
        try:
            provider = get_provider(req.provider, req.profile)
        except ProviderError as exc:
            raise HTTPException(400, str(exc)) from exc
        ts = run_trials(s, SCENARIOS[req.scenario_id], provider, req.mode, req.trials)
        compute_correlations(s)
        return trial_set_dict(ts)

    @app.get("/api/redteam/trials")
    def list_trials(
        scenario: str | None = Query(default=None, max_length=64),
        s: Session = Depends(session),
    ) -> list[dict[str, Any]]:
        from agentshield.models import TrialSet
        from agentshield.services.trials import trial_set_dict

        stmt = select(TrialSet).options(selectinload(TrialSet.scenario)).order_by(TrialSet.created_at.desc())
        if scenario:
            stmt = stmt.where(TrialSet.scenario_fk == scenario)
        return [trial_set_dict(t) for t in s.scalars(stmt).all()]

    @app.post("/api/redteam/run-all", dependencies=[Depends(require_token)])
    def run_all(req: RunAllRequest, s: Session = Depends(session)) -> list[dict[str, Any]]:
        from agentshield.models import new_id

        batch = new_id("batch")
        runs = [_run(s, sid, m, req.provider, req.profile, batch) for sid in SCENARIOS for m in req.modes]
        compute_correlations(s)
        return [q.run_summary(r) for r in runs]

    def _filtered_runs(
        s: Session, scenario: str | None, mode: str | None, outcome: str | None, provider: str | None
    ) -> list[TestRun]:
        stmt = select(TestRun).options(selectinload(TestRun.scenario)).order_by(TestRun.started_at.desc())
        if scenario:
            stmt = stmt.where(TestRun.scenario_fk == scenario)
        if mode:
            stmt = stmt.where(TestRun.policy_mode == mode)
        if outcome:
            stmt = stmt.where(TestRun.outcome == outcome)
        if provider:
            stmt = stmt.where(TestRun.provider == provider)
        return list(s.scalars(stmt).all())

    @app.get("/api/redteam/runs")
    def list_runs(
        scenario: str | None = Query(default=None, max_length=64),
        mode: str | None = Query(default=None, max_length=16),
        outcome: str | None = Query(default=None, max_length=16),
        provider: str | None = Query(default=None, max_length=32),
        limit: int = Query(default=200, ge=1, le=1000),
        s: Session = Depends(session),
    ) -> list[dict[str, Any]]:
        return [q.run_summary(r) for r in _filtered_runs(s, scenario, mode, outcome, provider)[:limit]]

    @app.get("/api/redteam/runs/export")
    def export_runs(format: Literal["json", "csv"] = "json", s: Session = Depends(session)) -> Response:
        runs = _filtered_runs(s, None, None, None, None)
        if format == "csv":
            return PlainTextResponse(
                q.to_csv([q.run_summary(r) for r in runs], q.RUN_CSV_FIELDS),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=agentshield-runs.csv"},
            )
        return JSONResponse(
            [q.run_detail(r) for r in runs],
            headers={"Content-Disposition": "attachment; filename=agentshield-runs.json"},
        )

    @app.get("/api/redteam/runs/{run_id}")
    def get_run(run_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        r = s.get(TestRun, run_id)
        if r is None:
            raise HTTPException(404, "run not found")
        return q.run_detail(r)

    @app.get("/api/tool-calls")
    def list_tool_calls(
        decision: Literal["allow", "deny"] | None = None,
        tool: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=500, ge=1, le=2000),
        s: Session = Depends(session),
    ) -> list[dict[str, Any]]:
        stmt = (
            select(ToolCallAttempt)
            .options(selectinload(ToolCallAttempt.decision), selectinload(ToolCallAttempt.run))
            .order_by(ToolCallAttempt.proposed_at.desc())
        )
        if tool:
            stmt = stmt.where(ToolCallAttempt.tool_name == tool)
        rows = s.scalars(stmt).all()
        out = []
        for a in rows:
            if decision and (a.decision is None or a.decision.decision != decision):
                continue
            out.append(
                {
                    "id": a.id,
                    "run_id": a.run_fk,
                    "scenario_id": a.run.scenario_fk,
                    "policy_mode": a.run.policy_mode,
                    "provider": a.run.provider,
                    "is_simulated": a.run.is_simulated,
                    "seq": a.seq,
                    "turn": a.turn,
                    "tool": a.tool_name,
                    "arguments": a.arguments,
                    "untrusted_context": a.untrusted_context,
                    "executed": a.executed,
                    "decision": a.decision.decision if a.decision else None,
                    "rule_ids": a.decision.rule_ids if a.decision else [],
                    "reasons": a.decision.reasons if a.decision else [],
                    "approval": a.decision.approval if a.decision else None,
                    "proposed_at": q._iso(a.proposed_at),
                }
            )
            if len(out) >= limit:
                break
        return out

    # -- correlation -------------------------------------------------------------------------
    @app.get("/api/correlations")
    def list_correlations(s: Session = Depends(session)) -> list[dict[str, Any]]:
        rows = s.scalars(select(RiskCorrelation)).all()
        return sorted((q.correlation_dict(c) for c in rows), key=lambda c: SEVERITY_RANK.get(c["severity"], 9))

    @app.post("/api/correlations/recompute", dependencies=[Depends(require_token)])
    def recompute(s: Session = Depends(session)) -> list[dict[str, Any]]:
        return [q.correlation_dict(c) for c in compute_correlations(s)]

    # -- demo --------------------------------------------------------------------------------
    @app.post("/api/demo", dependencies=[Depends(require_token)])
    def demo(s: Session = Depends(session)) -> dict[str, Any]:
        return run_demo(s)

    # -- optional static dashboard ------------------------------------------------------------
    static_dir = Path(os.environ.get("AGENTSHIELD_STATIC_DIR", Path.cwd() / "frontend" / "dist"))
    if (static_dir / "index.html").is_file():
        app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            if path.startswith("api/"):
                raise HTTPException(404)
            candidate = (static_dir / path).resolve()
            if path and candidate.is_file() and candidate.is_relative_to(static_dir.resolve()):
                return FileResponse(candidate)
            return FileResponse(static_dir / "index.html")

    return app
