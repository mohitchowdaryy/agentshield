# Implementation Plan

## Starting point

The workspace was empty; the project was initialized from scratch.

## Minimum complete vertical slice

`agentshield demo` must, with no credentials:

1. Create the SQLite database through Alembic.
2. Run the demo cloud collector through the real rule engine and persist
   deduplicated findings.
3. Run three red-team scenarios (direct injection, indirect injection,
   tool-output injection) against the deterministic simulator in both
   `vulnerable` and `protected` policy modes, persisting every model
   interaction, proposed call, authorization decision and executed call.
4. Evaluate each run from evidence and compute correlations.
5. Serve the results through the API and dashboard, labeled as demo/simulated.

## Milestones

### Milestone 1 — Working MVP
Scaffold, config, ORM + Alembic, redaction, cloud rule engine with demo
fixture, IAM policy parser, synthetic workspace + tools, gateway, simulator
provider, agent loop, three scenarios, evaluator, correlation rules, FastAPI,
Typer CLI, React dashboard (all eight pages, data-driven), pytest suite,
README.

### Milestone 2 — Real integrations
boto3 read-only AWS collector (pagination, throttling retries, AccessDenied as
collection gaps) tested with Moto; Anthropic provider adapter with structured
tool calling, timeouts, retries, usage and cost estimate; `scan aws` and
`--provider anthropic` CLI paths.

### Milestone 3 — Research platform
Scenario catalog to ≥10 cases (jailbreak resistance, multi-step manipulation,
excessive agency, tool-output contamination); aggregate metrics computed from
persisted runs; JSON/CSV evidence export; CI security regression tests.

### Milestone 4 — Portfolio release
UI polish, Docker, GitHub Actions, security review, documentation, resume
bullets from verified facts only.

## Dependencies

Backend (pinned in `pyproject.toml`): FastAPI, Pydantic v2, SQLAlchemy 2,
Alembic, Typer, Rich, boto3, httpx, anthropic. Dev: pytest, moto, ruff, mypy,
pip-audit. Frontend: React, TypeScript, Vite, Tailwind CSS, Recharts,
@xyflow/react (React Flow), react-router.

## External credentials (optional)

| Credential | Used for | How supplied |
|---|---|---|
| AWS profile / role | `agentshield scan aws` | Standard credential chain (`AWS_PROFILE`, SSO, instance role). Never stored. |
| `ANTHROPIC_API_KEY` | `--provider anthropic` red-team runs | Environment variable. Runs incur provider charges. |

Neither is required for the demo or for the test suite.

## Key decisions

- **SQLite first** with SQLAlchemy so that Postgres is a connection-string change.
- **Collect/evaluate split** so live and demo scans share every rule.
- **In-memory synthetic workspace** for agent tools, so even the vulnerable
  mode cannot touch the real filesystem or network.
- **Simulator is labeled everywhere** (`provider=simulator`, `is_simulated=true`)
  and shown with a distinct badge in the UI.
- **shadcn/ui**: the dashboard uses hand-written components in the shadcn
  style (Tailwind + CSS variables) rather than the shadcn CLI, to keep the
  build reproducible offline.
