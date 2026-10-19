# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open a public issue. Include reproduction steps and the affected
version or commit. We aim to acknowledge reports within 5 business days.

## Scope

In scope: the AgentShield API, CLI, dashboard, gateway, collectors and anything that could cause
AgentShield to modify cloud resources, leak credentials or evidence, send data off the machine
outside the documented model-provider call, or escape the agent tool sandbox.

Out of scope: findings that require the operator to deliberately weaken defaults (binding to
`0.0.0.0` without a token, granting the scanner write permissions), and the intentionally
permissive `vulnerable` policy mode, which only operates inside the synthetic sandbox.

## Security design commitments

- Cloud scanning is read-only and enforced in code (`get_`/`list_`/`describe_` allowlist).
- No credentials are stored; AWS and Anthropic credentials come from their standard SDK chains.
- Agent tools never touch the real filesystem or network.
- Authorization decisions are deterministic and never delegated to a model.
- Evidence is redacted before storage and export.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [docs/limitations.md](docs/limitations.md).

## Responsible use

Use AgentShield only against agents and cloud accounts you own or are explicitly authorized to
test.
