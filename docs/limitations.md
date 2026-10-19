# Limitations

AgentShield is a research MVP. These limits are known and deliberate; none of them is hidden by the UI.

## Results and claims

- **Simulator ≠ model.** The `simulator` provider is a deterministic rule engine, not a language
  model. Its `naive` profile follows imperative directives by regex; its `resistant` profile
  ignores them. Simulated runs validate the gateway, evaluator and evidence pipeline only.
- **Live-model results are single samples.** One run of a scenario against a real model says
  little about that model's attack success rate. Repeated runs and aggregate statistics are on the
  roadmap; until then do not quote a "success rate" from a handful of runs.
- **Cloud findings are configuration risk.** Rules read identity and resource policies
  statically. They do not evaluate SCPs, permission boundaries, session policies, most condition
  keys, KMS key policies, ACLs or VPC endpoint policies. `exploitability` is always
  `not_validated`.
- **Correlations are modeled.** The agent's tools are sandboxed and never use AWS credentials, so
  no correlation exercises a cloud step. `agent_step_observed_in_simulation` means only that the
  agent-side step (untrusted content steering tool use) was observed in a sandbox run.
- **Data classification** for CORR-003 relies on a `data-classification=confidential` bucket tag.

## Coverage

- AWS only; one partition per scan. S3, IAM roles, root account summary and CloudTrail are
  covered. IAM users and groups, EC2, KMS, Lambda, Organizations and GCP are not.
- The AWS collector is tested with Moto and monkeypatched clients, not against a real account in CI.
  Moto's fidelity for some APIs (for example S3 Control) is limited.
- A scan with collection gaps does not auto-resolve findings (it cannot tell "fixed" from "not
  visible").
- Three red-team scenarios today; the target is ten or more.
- DLP in the gateway matches known markers only (canary tokens, `CONFIDENTIAL`). It is not a
  general data-loss-prevention engine.
- The Anthropic adapter is unit-tested with a fake client. It has not been exercised against the
  live API in this repository's automated tests (that would incur charges).

## Platform security

- Single-user local tool: no authentication beyond an optional shared bearer token for mutating
  endpoints, no RBAC, no multi-tenancy.
- SQLite is not tamper-evident; evidence integrity relies on the local file system.
- Redaction is pattern-based and can miss unknown secret formats.
- The dashboard is served without a Content-Security-Policy header.
- Docker images were not built locally (Docker Desktop not running); the CI `docker` job builds both
  images and smoke-tests the API container's health endpoints.
- Live-model evidence so far is 31 runs of one small local model (`qwen2.5:7b`); see
  [live-results.md](live-results.md). It is a small sample, not a rate.

## Not production-ready until

1. Authentication and authorization for the API and dashboard.
2. Postgres with migrations tested on it, and backups.
3. A threat-model review of any deployment that exposes the API beyond localhost.
4. Repeated-trial statistics for live-model evaluations.
