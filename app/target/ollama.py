"""Ollama/local model adapter."""

from __future__ import annotations

import httpx

from app.target.base import TargetAdapter, TargetRequest, TargetResponse


class OllamaAdapter(TargetAdapter):
    async def _send(self, request: TargetRequest) -> TargetResponse:
        url = f"{self.endpoint.rstrip('/')}/api/chat"
        payload = {
            "model": self.model,
            "messages": request.messages,
            "stream": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }

        async with self._client() as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

        message = data.get("message", {})
        content = message.get("content", "")

        return TargetResponse(
            response=content,
            tool_calls=[],
            metadata={"provider": "ollama", "model": self.model},
        )
