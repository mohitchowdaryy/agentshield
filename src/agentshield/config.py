"""Runtime settings. Every value has a safe local default; secrets come only from the environment."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_db_url() -> str:
    data_dir = Path.cwd() / ".agentshield"
    return f"sqlite:///{(data_dir / 'agentshield.db').as_posix()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTSHIELD_", env_file=".env", extra="ignore")

    database_url: str = Field(default_factory=_default_db_url)

    # API server
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    # When set, mutating API endpoints require `Authorization: Bearer <token>`.
    api_token: SecretStr | None = None
    max_request_bytes: int = 256 * 1024

    # Agent runtime
    max_agent_turns: int = 6
    model_timeout_seconds: float = 60.0
    model_max_retries: int = 2
    model_max_output_tokens: int = 8000

    # LLM provider. The API key is read by the provider SDK from ANTHROPIC_API_KEY (or an
    # `ant auth login` profile); it is never written to the database.
    anthropic_model: str = "claude-opus-5-5"
    anthropic_effort: str = "medium"
    # Server-side refusal fallback: a declined turn is re-run on Anthropic's recommended fallback model.
    # The evidence records which model served each turn.
    anthropic_refusal_fallback: bool = True

    # Local model via Ollama (free, no API key). Keep the URL on localhost so prompts stay on this machine.
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b"
    ollama_timeout_seconds: float = 180.0
    # None uses the model's default sampling, so repeated trials can differ.
    ollama_temperature: float | None = None

    # Infrastructure-as-Code scanning (static; no deployment, no cloud credentials)
    # Path to a `checkov` executable or to the Python interpreter of a virtualenv that has Checkov.
    checkov_path: str | None = None
    checkov_timeout_seconds: float = 300.0
    iac_lab_dir: str = "terraform-lab"

    # AWS scanning
    aws_profile: str | None = None
    aws_regions: list[str] = []
    aws_max_attempts: int = 5


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
