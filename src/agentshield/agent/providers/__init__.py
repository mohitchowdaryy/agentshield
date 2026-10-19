"""Provider registry."""

from __future__ import annotations

from agentshield.agent.providers.base import ModelProvider, ProviderError
from agentshield.agent.providers.simulator import SimulatorProvider

PROVIDERS = ("simulator", "anthropic", "ollama")


def get_provider(name: str, profile: str = "naive") -> ModelProvider:
    if name == "simulator":
        if profile not in ("naive", "resistant"):
            raise ProviderError("simulator profile must be 'naive' or 'resistant'")
        return SimulatorProvider(profile)  # type: ignore[arg-type]
    if name == "anthropic":
        from agentshield.agent.providers.anthropic_provider import AnthropicProvider
        from agentshield.config import get_settings

        s = get_settings()
        return AnthropicProvider(
            s.anthropic_model,
            effort=s.anthropic_effort,
            timeout=s.model_timeout_seconds,
            max_retries=s.model_max_retries,
            refusal_fallback=s.anthropic_refusal_fallback,
        )
    if name == "ollama":
        from agentshield.agent.providers.ollama_provider import OllamaProvider
        from agentshield.config import get_settings

        s = get_settings()
        return OllamaProvider(
            s.ollama_model,
            base_url=s.ollama_base_url,
            timeout=s.ollama_timeout_seconds,
            max_retries=s.model_max_retries,
            temperature=s.ollama_temperature,
        )
    raise ProviderError(f"unknown provider '{name}'. Available: {', '.join(PROVIDERS)}")
