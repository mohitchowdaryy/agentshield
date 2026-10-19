from __future__ import annotations

import os

import pytest

# Never let the test suite reach real AWS or a real model provider.
for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "ANTHROPIC_API_KEY"):
    os.environ.pop(var, None)
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"  # noqa: S105 - moto dummy credentials
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_CONFIG_FILE"] = os.devnull
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull


@pytest.fixture()
def db_url(tmp_path, monkeypatch):
    from agentshield import db
    from agentshield.config import get_settings

    url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", url)
    monkeypatch.delenv("AGENTSHIELD_API_TOKEN", raising=False)
    get_settings.cache_clear()
    db.upgrade_database(url)
    yield url
    get_settings.cache_clear()
    engine = db._engines.pop(url, None)
    if engine is not None:
        engine.dispose()


@pytest.fixture()
def session(db_url):
    from agentshield.db import session_scope

    with session_scope(db_url) as s:
        yield s
