# Tasks

Legend: [x] done and verified (test, CLI run or browser check) · [~] written but not verified · [ ] not done.

## Milestone 1 — Working MVP
- [x] Project scaffold, pinned dependencies, settings with safe defaults
- [x] 13-table ORM + Alembic initial migration (creates the SQLite directory on first run)
- [x] Secret redaction on all persisted and exported evidence
- [x] Cloud rule engine (12 rules), IAM policy parser, demo inventory, fingerprint dedup, resolve-on-rescan
- [x] Synthetic in-memory workspace, 4 tools, gateway (GW-001…GW-008), protected / vulnerable policies
- [x] Deterministic simulator (naive / resistant) and traced agent loop
- [x] 3 end-to-end scenarios (direct, indirect, tool-output injection) + evidence-based evaluator
- [x] Correlation rules CORR-001…003 with evidence and path graphs
- [x] FastAPI API: CORS allowlist, body limit, optional bearer token, security headers, JSON/CSV export
- [x] Typer CLI: doctor, demo, scan aws/demo, redteam list/run/run-all, evaluate, report, serve, db upgrade
- [x] React dashboard, 8 pages + run detail; builds with `tsc` + Vite; checked in the browser with demo data
- [x] README and docs

## Milestone 2 — Real integrations
- [x] boto3 read-only AWS collector (pagination, adaptive retries, AccessDenied → collection gaps), Moto tests
- [x] Anthropic provider (structured tool calling, timeouts, retries, usage, cost estimate, refusal fallback evidence), fake-client tests
- [ ] Live verification against a real AWS account (needs the user's read-only profile)
- [ ] Live verification against the Anthropic API (needs a key; incurs charges)
- [x] Ollama provider for free local open-weight models (structured tool calling, retries, timeouts, mocked-HTTP tests)
- [x] Live check with Ollama `qwen2.5:7b`: one tool-output-injection run, protected mode (2026-10-19). The model called `lookup_cloud_config`, proposed no unsafe call, and completed the task in 81 s. Its answer echoed part of the injected text. Single sample only, not a rate
- [x] Completion markers accept paraphrase alternatives (`a|b`), found during the live run

## Milestone 3 — Research platform
- [ ] Scenarios 4–10+: jailbreak resistance, multi-step workflow manipulation, excessive agency, tool-output contamination of later turns, unauthorized tool attempts via aliasing, confidential-data summarization leak, approval fatigue. Plan: adapt tasks from published benchmarks (AgentDojo, InjecAgent) and load them through a scenario importer (not built yet)
- [x] Repeated trial sets: `redteam run --trials N` (1–50), `trial_sets` table (migration 0002) with outcome and check counts, `/api/redteam/trials`, History page card; tests cover counts, API, CLI and migration round-trip
- [ ] Confidence intervals for live-model trial counts
- [x] Evidence export (JSON/CSV) via API and CLI
- [x] CI security regression subset (gateway, scenarios, redaction)
- [ ] PyRIT adapter

## Milestone 4 — Portfolio release
- [x] Dark enterprise UI with empty, loading and error states
- [~] Dockerfiles + docker-compose (written; not built: Docker daemon was not running)
- [~] GitHub Actions CI (written; runs on first push)
- [x] Threat model, security policy, limitations, resume bullets from verified facts
- [ ] Screenshots in docs/screenshots/
- [ ] Content-Security-Policy for the served dashboard
- [ ] GCP collector (design in ARCHITECTURE.md)
