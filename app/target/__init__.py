"""Target adapter factory."""

from __future__ import annotations

from typing import Any

from app.target.base import MockTargetAdapter, TargetAdapter, TargetConfig
from app.target.custom_api import CustomHTTPAdapter
from app.target.gemini import GeminiAdapter
from app.target.ollama import OllamaAdapter
from app.target.openai import OpenAIAdapter


def create_target_adapter(config: TargetConfig, secret_manager: Any) -> TargetAdapter:
    common = dict(
        model=config.model,
        endpoint=config.endpoint,
        secret_handle=config.api_key_handle,
        secret_manager=secret_manager,
        timeout=config.timeout,
        max_response_chars=config.max_response_chars,
        extra=config.extra,
    )

    provider = config.provider.lower()

    if provider == "mock":
        return MockTargetAdapter(**common)

    if provider in {"openai", "openai_compatible"}:
        return OpenAIAdapter(**common)

    if provider == "gemini":
        return GeminiAdapter(**common)

    if provider == "ollama":
        return OllamaAdapter(**common)

    if provider in {"custom", "custom_http", "http"}:
        return CustomHTTPAdapter(**common)

    raise ValueError(f"Unsupported target provider: {provider}")
