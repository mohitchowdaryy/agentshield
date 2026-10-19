# Resume bullet drafts

Every claim below is backed by code and tests in this repository as of this version. Update the
numbers if the code changes.

- Built **AgentShield**, an open-source AI agent security platform (Python, FastAPI, SQLAlchemy,
  React/TypeScript) that red-teams a tool-using LLM agent with prompt-injection scenarios and
  enforces a deterministic tool-authorization gateway; 135 automated tests, no real cloud or LLM
  calls in CI.
- Designed a default-deny gateway with 8 rule types (allowlists, Pydantic argument validation,
  path-traversal rejection, resource scopes, destination allowlists, canary-based DLP,
  untrusted-context human approval, call budgets). In the bundled scenarios it turned all 3
  sandboxed exfiltration and disclosure attacks that succeed under a permissive policy into failed
  attacks, while the legitimate task still completed.
- Implemented a read-only AWS posture scanner (boto3, 12 rules across S3, IAM, root account and
  CloudTrail) with pagination, adaptive retries, AccessDenied-tolerant partial results, and
  fingerprint-based deduplication; tested with Moto.
- Built an evidence-first evaluator that separates "model saw the payload", "model proposed an
  unsafe call", "gateway decision" and "violation executed", and can re-derive verdicts from
  persisted evidence; mapped scenarios to OWASP LLM Top 10 2025 and MITRE ATLAS.
- Added cloud-to-agent risk correlation that links IAM/S3 findings to an agent's identity, data
  sources and red-team runs, labeling paths as modeled vs observed instead of claiming
  exploitability.

- Evaluated a local open-weight model (`qwen2.5:7b` via Ollama) across 30 live runs (3 injection
  scenarios x 2 gateway policies x 5 trials): 0 unsafe tool calls proposed, and identified
  over-refusal under direct injection (legitimate task completed in 1 of 10 runs).

Do not claim: attack success rates (5 trials per cell is not a rate), production deployment, or GCP support. None of these
exist yet.
