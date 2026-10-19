"""AgentShield command-line interface."""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from agentshield import __version__
from agentshield.config import get_settings

app = typer.Typer(
    help="AgentShield: AI agent red-teaming and cloud posture research platform.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
scan_app = typer.Typer(help="Cloud posture scans (read-only).", no_args_is_help=True)
redteam_app = typer.Typer(help="AI agent red-team scenarios against the local test agent.", no_args_is_help=True)
db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")
app.add_typer(redteam_app, name="redteam")
app.add_typer(db_app, name="db")

console = Console()
err = Console(stderr=True)

OUTCOME_STYLE = {"succeeded": "bold red", "failed": "green", "inconclusive": "yellow", "errored": "magenta"}
SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _db() -> Any:
    from agentshield.db import session_scope, upgrade_database

    upgrade_database()
    return session_scope()


def _runs_table(rows: list[dict[str, Any]], title: str) -> Table:
    t = Table(title=title)
    for col in ("run id", "scenario", "provider/model", "mode", "outcome", "defense", "task done", "gateway denials"):
        t.add_column(col)
    for r in rows:
        c = r.get("checks", {})
        t.add_row(
            r["id"],
            r["scenario_id"],
            r["model"] + (" [SIM]" if r["is_simulated"] else ""),
            r["policy_mode"],
            f"[{OUTCOME_STYLE.get(r['outcome'], '')}]{r['outcome']}[/]",
            r.get("defense_layer") or "-",
            "yes" if c.get("legitimate_task_completed") else "no",
            str(c.get("unsafe_calls_denied_by_gateway", 0)),
        )
    return t


@app.command()
def version() -> None:
    """Print the AgentShield version."""
    console.print(__version__)


@app.command()
def doctor(
    check_aws: Annotated[bool, typer.Option(help="Call STS GetCallerIdentity to verify AWS credentials.")] = False,
) -> None:
    """Check the local environment, database and optional integrations."""
    settings = get_settings()
    ok = True
    t = Table(title="AgentShield doctor", show_header=True)
    t.add_column("check")
    t.add_column("status")
    t.add_column("detail")

    py_ok = sys.version_info >= (3, 11)
    ok &= py_ok
    t.add_row("python", "[green]ok[/]" if py_ok else "[red]fail[/]", platform.python_version())
    try:
        from agentshield.db import upgrade_database

        upgrade_database()
        t.add_row("database", "[green]ok[/]", settings.database_url.split("///")[-1])
    except Exception as exc:  # noqa: BLE001
        ok = False
        t.add_row("database", "[red]fail[/]", str(exc)[:200])

    t.add_row("simulator provider", "[green]ok[/]", "offline, deterministic (labeled SIMULATED)")
    key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    try:
        import anthropic  # noqa: F401

        sdk = "installed"
    except ImportError:
        sdk = "not installed (pip install 'agentshield[anthropic]')"
    t.add_row(
        "anthropic provider",
        "[green]configured[/]" if key else "[yellow]not configured[/]",
        f"ANTHROPIC_API_KEY {'set' if key else 'unset'}; SDK {sdk}; model {settings.anthropic_model}",
    )

    import boto3

    creds = (
        boto3.Session(profile_name=settings.aws_profile).get_credentials()
        if settings.aws_profile
        else boto3.Session().get_credentials()
    )
    aws_detail = f"credential source: {creds.method}" if creds else "no credentials in the default chain"
    aws_status = "[green]found[/]" if creds else "[yellow]not configured[/]"
    if check_aws and creds:
        try:
            ident = boto3.client("sts").get_caller_identity()
            aws_detail += f"; account {ident['Account']}, principal {ident['Arn']}"
        except Exception as exc:  # noqa: BLE001
            aws_status, aws_detail = "[red]fail[/]", str(exc)[:200]
    t.add_row("aws credentials", aws_status, aws_detail)

    dist = Path.cwd() / "frontend" / "dist" / "index.html"
    t.add_row(
        "dashboard build",
        "[green]found[/]" if dist.is_file() else "[yellow]not built[/]",
        str(dist.parent) if dist.is_file() else "cd frontend && npm ci && npm run build",
    )
    t.add_row(
        "api bind",
        "[green]ok[/]" if settings.host in ("127.0.0.1", "localhost") else "[yellow]exposed[/]",
        f"{settings.host}:{settings.port}",
    )
    console.print(t)
    raise typer.Exit(0 if ok else 1)


@app.command()
def demo() -> None:
    """Run the full offline demo: demo cloud scan, simulated red-team matrix, correlation."""
    from agentshield.models import TestRun
    from agentshield.services.demo import run_demo
    from agentshield.services.queries import run_summary

    with _db() as s:
        result = run_demo(s)
        rows = [run_summary(s.get(TestRun, r["id"])) for r in result["runs"]]
        console.print(f"[bold]Demo cloud scan[/] {result['scan_id']} (source=demo): {result['scan_summary']}")
        console.print(_runs_table(rows, "Red-team runs (SIMULATED agent, synthetic data)"))
        console.print(f"Correlations computed: {len(result['correlations'])}")
    console.print("Start the dashboard with [bold]agentshield serve[/] and open http://127.0.0.1:8000")


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Apply database migrations."""
    from agentshield.db import upgrade_database

    upgrade_database()
    console.print("database is at the latest migration")


def _print_scan(scan_dict: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    console.print(
        f"[bold]Scan {scan_dict['id']}[/] source={scan_dict['source']} status={scan_dict['status']} "
        f"account={scan_dict['account_id']} regions={','.join(scan_dict['regions'])}"
    )
    t = Table(title=f"{len(findings)} findings (configuration risk; exploitability not validated)")
    for col in ("severity", "rule", "resource", "title"):
        t.add_column(col)
    for f in findings:
        t.add_row(
            f"[{SEV_STYLE.get(f['severity'], '')}]{f['severity']}[/]", f["rule_id"], f["resource_arn"], f["title"]
        )
    console.print(t)
    for g in scan_dict["collection_gaps"]:
        err.print(f"[yellow]gap[/] {g['service']}:{g['operation']} {g.get('resource') or ''} -> {g['error_code']}")


def _scan(collector: Any) -> None:
    from agentshield.correlation.engine import compute_correlations
    from agentshield.models import Finding, FindingObservation
    from agentshield.services.queries import finding_dict, scan_dict
    from agentshield.services.scans import run_scan

    with _db() as s:
        scan = run_scan(s, collector)
        compute_correlations(s)
        rows = s.scalars(
            select(Finding)
            .join(FindingObservation, FindingObservation.finding_fk == Finding.id)
            .where(FindingObservation.scan_fk == scan.id)
        ).all()
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        _print_scan(scan_dict(scan), sorted((finding_dict(f) for f in rows), key=lambda f: order[f["severity"]]))


@scan_app.command("aws")
def scan_aws(
    profile: Annotated[str | None, typer.Option(help="AWS profile name (default: standard credential chain).")] = None,
    region: Annotated[list[str] | None, typer.Option("--region", "-r", help="Region(s) to scan; repeatable.")] = None,
) -> None:
    """Read-only AWS posture scan using the standard credential chain."""
    from agentshield.cloud.aws import AwsCollector, AwsScanError

    settings = get_settings()
    try:
        collector = AwsCollector(
            profile=profile or settings.aws_profile,
            regions=region or settings.aws_regions,
            max_attempts=settings.aws_max_attempts,
        )
        _scan(collector)
    except AwsScanError as exc:
        err.print(f"[red]AWS scan failed:[/] {exc}")
        raise typer.Exit(2) from exc


@scan_app.command("demo")
def scan_demo() -> None:
    """Scan the bundled synthetic demo inventory (no AWS access)."""
    from agentshield.cloud.demo import DemoCollector

    _scan(DemoCollector())


@redteam_app.command("list")
def redteam_list() -> None:
    """List available red-team scenarios."""
    from agentshield.redteam.scenarios import SCENARIOS

    t = Table(title="Red-team scenarios")
    for col in ("id", "severity", "entry point", "OWASP LLM", "MITRE ATLAS"):
        t.add_column(col)
    for s in SCENARIOS.values():
        t.add_row(s.id, s.severity, s.entry_point, "\n".join(s.mappings.owasp_llm), "\n".join(s.mappings.mitre_atlas))
    console.print(t)


class ConsoleApprover:
    name = "interactive console reviewer"

    def review(self, request: Any) -> bool:
        console.print(f"[bold yellow]Approval required[/] for {request.tool}: {request.reason}")
        console.print_json(json.dumps(request.arguments)[:2000])
        return typer.confirm("Approve this tool call?", default=False)


def _execute(scenario_ids: list[str], modes: list[str], provider: str, profile: str, interactive: bool) -> None:
    from agentshield.agent.providers import ProviderError, get_provider
    from agentshield.correlation.engine import compute_correlations
    from agentshield.models import new_id
    from agentshield.redteam.engine import run_scenario
    from agentshield.redteam.scenarios import get_scenario
    from agentshield.services.queries import run_summary
    from agentshield.services.redteam import persist_run

    try:
        scenarios = [get_scenario(sid) for sid in scenario_ids]
        prov = get_provider(provider, profile)
    except (KeyError, ProviderError) as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc
    if not prov.is_simulated:
        console.print(
            f"[yellow]Live model run with {prov.model}: this sends synthetic scenario data to the "
            "provider and incurs API charges.[/]"
        )
    batch = new_id("batch") if len(scenarios) * len(modes) > 1 else None
    rows = []
    with _db() as s:
        for sc in scenarios:
            for mode in modes:
                result = run_scenario(sc, prov, mode, approver=ConsoleApprover() if interactive else None)  # type: ignore[arg-type]
                rows.append(run_summary(persist_run(s, result, batch)))
        compute_correlations(s)
    console.print(_runs_table(rows, "Red-team results" + (" (SIMULATED)" if prov.is_simulated else "")))
    console.print("Inspect a run: agentshield evaluate --run-id <id>")


@redteam_app.command("run")
def redteam_run(
    scenario: Annotated[str, typer.Option(help="Scenario id (see `agentshield redteam list`).")],
    mode: Annotated[str, typer.Option(help="Gateway policy mode: protected or vulnerable.")] = "protected",
    provider: Annotated[str, typer.Option(help="Model provider: simulator or anthropic.")] = "simulator",
    profile: Annotated[str, typer.Option(help="Simulator behavior profile: naive or resistant.")] = "naive",
    interactive_approval: Annotated[bool, typer.Option(help="Ask on the console for approval-gated calls.")] = False,
    trials: Annotated[
        int, typer.Option(min=1, max=50, help="Repeat the scenario N times and store outcome counts.")
    ] = 1,
) -> None:
    """Run one scenario against the local test agent."""
    if mode not in ("protected", "vulnerable"):
        err.print("[red]--mode must be 'protected' or 'vulnerable'[/]")
        raise typer.Exit(2)
    if trials > 1:
        _execute_trials(scenario, mode, provider, profile, trials, interactive_approval)
        return
    _execute([scenario], [mode], provider, profile, interactive_approval)


def _execute_trials(scenario_id: str, mode: str, provider: str, profile: str, trials: int, interactive: bool) -> None:
    from agentshield.agent.providers import ProviderError, get_provider
    from agentshield.correlation.engine import compute_correlations
    from agentshield.redteam.scenarios import get_scenario
    from agentshield.services.trials import OUTCOMES, run_trials, trial_set_dict

    try:
        sc = get_scenario(scenario_id)
        prov = get_provider(provider, profile)
    except (KeyError, ProviderError) as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc
    if not prov.is_simulated:
        console.print(
            f"[yellow]Live model run with {prov.model}: {trials} trials send synthetic scenario data to the "
            "provider and incur API charges.[/]"
        )
    with _db() as s:
        ts = run_trials(s, sc, prov, mode, trials, ConsoleApprover() if interactive else None)  # type: ignore[arg-type]
        compute_correlations(s)
        d = trial_set_dict(ts)
    t = Table(title=f"{trials} trials: {sc.id} ({mode}, {d['model']})" + (" [SIMULATED]" if d["is_simulated"] else ""))
    for col in ("trial set", *OUTCOMES):
        t.add_column(col)
    t.add_row(d["id"], *(str(d["outcome_counts"].get(o, 0)) for o in OUTCOMES))
    console.print(t)
    checks = d["check_counts"]
    console.print(
        f"saw payload in {checks.get('saw_malicious_content', 0)}/{trials} | unsafe proposal in "
        f"{checks.get('unsafe_tool_call_proposed', 0)}/{trials} | violation executed in "
        f"{checks.get('simulated_violation_executed', 0)}/{trials} | task completed in "
        f"{checks.get('legitimate_task_completed', 0)}/{trials}"
    )
    if d["is_simulated"]:
        console.print("[dim]The simulator is deterministic: every trial is identical. Counts are not a rate.[/]")


@redteam_app.command("run-all")
def redteam_run_all(
    mode: Annotated[
        list[str] | None, typer.Option(help="Mode(s); repeatable. Default: vulnerable and protected.")
    ] = None,
    provider: Annotated[str, typer.Option(help="Model provider: simulator or anthropic.")] = "simulator",
    profile: Annotated[str, typer.Option(help="Simulator behavior profile: naive or resistant.")] = "naive",
) -> None:
    """Run every scenario in each requested mode."""
    from agentshield.redteam.scenarios import SCENARIOS

    modes = mode or ["vulnerable", "protected"]
    if any(m not in ("protected", "vulnerable") for m in modes):
        err.print("[red]--mode must be 'protected' or 'vulnerable'[/]")
        raise typer.Exit(2)
    _execute(list(SCENARIOS), modes, provider, profile, False)


@app.command()
def evaluate(
    run_id: Annotated[str, typer.Option(help="Run id to evaluate.")],
    save: Annotated[bool, typer.Option(help="Store the re-computed evaluation.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print the evaluation as JSON.")] = False,
) -> None:
    """Re-evaluate a persisted run from its stored evidence and print the trace verdict."""
    from agentshield.models import TestRun
    from agentshield.redteam.evaluator import evaluate as do_evaluate
    from agentshield.redteam.scenarios import get_scenario
    from agentshield.services.reconstruct import trace_from_run

    with _db() as s:
        run = s.get(TestRun, run_id)
        if run is None:
            err.print(f"[red]run '{run_id}' not found[/]")
            raise typer.Exit(2)
        ev = do_evaluate(get_scenario(run.scenario_fk), trace_from_run(run))
        if save:
            run.evaluation = {**run.evaluation, **ev}
            run.outcome = ev["outcome"]
        if as_json:
            console.print_json(json.dumps(ev, default=str))
            return
        console.print(
            f"[bold]{run.id}[/] scenario={run.scenario_fk} mode={run.policy_mode} model={run.model}"
            + (" [SIMULATED]" if run.is_simulated else "")
        )
        console.print(
            f"Outcome: [{OUTCOME_STYLE.get(ev['outcome'], '')}]{ev['outcome']}[/] "
            f"(defense layer: {ev['defense_layer']})"
        )
        console.print(ev["rationale"])
        for k, v in ev["checks"].items():
            console.print(f"  {k}: {v}")
        t = Table(title="Tool-call trace (proposed -> decision -> executed)")
        for col in ("#", "turn", "tool", "arguments", "untrusted ctx", "decision", "rules", "executed"):
            t.add_column(col)
        for a in run.attempts:
            d = a.decision
            t.add_row(
                str(a.seq),
                str(a.turn),
                a.tool_name,
                json.dumps(a.arguments)[:80],
                str(a.untrusted_context),
                d.decision if d else "-",
                ",".join(d.rule_ids) if d else "-",
                str(a.executed),
            )
        console.print(t)


@app.command()
def report(
    format: Annotated[str, typer.Option(help="json or csv.")] = "json",
    kind: Annotated[str, typer.Option(help="findings, runs, or all (json only).")] = "all",
    output: Annotated[Path | None, typer.Option(help="Write to a file instead of stdout.")] = None,
) -> None:
    """Export findings and red-team evidence."""
    from sqlalchemy.orm import selectinload

    from agentshield.models import Finding, RiskCorrelation, TestRun
    from agentshield.services import queries as q

    if format not in ("json", "csv") or kind not in ("findings", "runs", "all"):
        err.print("[red]--format must be json|csv and --kind findings|runs|all[/]")
        raise typer.Exit(2)
    if format == "csv" and kind == "all":
        err.print("[red]CSV export needs --kind findings or --kind runs[/]")
        raise typer.Exit(2)
    with _db() as s:
        findings = [q.finding_dict(f, detail=True) for f in s.scalars(select(Finding)).all()]
        runs = s.scalars(select(TestRun).options(selectinload(TestRun.scenario))).all()
        if format == "csv":
            text = (
                q.to_csv(findings, q.FINDING_CSV_FIELDS)
                if kind == "findings"
                else q.to_csv([q.run_summary(r) for r in runs], q.RUN_CSV_FIELDS)
            )
        else:
            payload: dict[str, Any] = {"generator": f"agentshield {__version__}"}
            if kind in ("findings", "all"):
                payload["findings"] = findings
            if kind in ("runs", "all"):
                payload["runs"] = [q.run_detail(r) for r in runs]
            if kind == "all":
                payload["overview"] = q.overview(s)
                payload["correlations"] = [q.correlation_dict(c) for c in s.scalars(select(RiskCorrelation)).all()]
            text = json.dumps(payload, indent=2, default=str)
    if output:
        output.write_text(text, encoding="utf-8")
        err.print(f"wrote {output}")
    else:
        sys.stdout.write(text + "\n")


@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Bind address (default 127.0.0.1).")] = None,
    port: Annotated[int | None, typer.Option(help="Port (default 8000).")] = None,
) -> None:
    """Start the API (and the built dashboard, if frontend/dist exists)."""
    import uvicorn

    from agentshield.api.app import create_app

    settings = get_settings()
    h, p = host or settings.host, port or settings.port
    if h not in ("127.0.0.1", "localhost", "::1"):
        err.print(f"[yellow]Warning: binding to {h} exposes findings and evidence beyond this machine.[/]")
    uvicorn.run(create_app(settings), host=h, port=p, log_level="info")


if __name__ == "__main__":
    app()
