"""Qwen / OpenAI-compatible evaluator model client."""

from __future__ import annotations

from typing import Any, Dict, List

import httpx


class ModelProviderError(RuntimeError):
    """Sanitized evaluator-model error."""


class QwenClient:
    """Client for Qwen-compatible chat completion endpoints."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str = "",
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout

    async def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> str:
        if not self.base_url:
            raise ModelProviderError("model endpoint not configured")

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                )

            if response.status_code == 401:
                raise ModelProviderError("model authentication failed")

            if response.status_code >= 400:
                raise ModelProviderError(
                    f"model provider error status={response.status_code}"
                )

            data = response.json()
            return data["choices"][0]["message"].get("content", "") or ""

        except httpx.HTTPError:
            raise ModelProviderError("model request failed") from None
