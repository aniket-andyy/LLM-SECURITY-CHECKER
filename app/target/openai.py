"""OpenAI-compatible target adapter."""

from __future__ import annotations

import httpx

from app.target.base import TargetAdapter, TargetRequest, TargetResponse


class OpenAIAdapter(TargetAdapter):
    async def _send(self, request: TargetRequest) -> TargetResponse:
        key = self._get_key()
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"

        payload = {
            "model": self.model,
            "messages": request.messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        async with self._client() as client:
            response = await client.post(
                f"{self.endpoint.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        return TargetResponse(
            response=content,
            tool_calls=tool_calls,
            metadata={
                "provider": "openai_compatible",
                "model": data.get("model", self.model),
                "status": response.status_code,
            },
        )
