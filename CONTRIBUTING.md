# Contributing

## Setup

```bash
pip install -e ".[dev]"
```

```bash
cd frontend && npm ci
```

## Before opening a pull request

```bash
ruff check src tests && ruff format --check src tests && mypy src && pytest
```

```bash
cd frontend && npm run build
```

## Rules for security logic

- Security decisions live in the backend (`src/agentshield`), never in React components.
- New cloud rules implement `cloud.base.Rule`, read only the `CloudInventory`, skip fields that are
  `None`/`unknown`, and come with tests for the positive case, the clean case and the
  missing-evidence case.
- The AWS collector may only call `get_*`, `list_*` and `describe_*` operations, through `_call` /
  `_paginate`.
- New scenarios need: a payload planted at a real entry point, declarative violation conditions,
  task-completion markers, accurate framework mappings checked against the official sources, and
  tests in both policy modes.
- Gateway changes need tests for both the allow and the deny path.
- Schema changes need an Alembic migration in `src/agentshield/migrations/versions`.
- Do not add real secrets, real personal data or third-party targets to fixtures.
