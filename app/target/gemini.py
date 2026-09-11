"""Gemini-compatible target adapter."""

from __future__ import annotations

from typing import Any, Dict, List

import httpx

from app.target.base import TargetAdapter, TargetRequest, TargetResponse


def _messages_to_gemini_contents(messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    contents: List[Dict[str, Any]] = []
    for message in messages:
        role = "user" if message.get("role") in {"user", "system"} else "model"
        contents.append({"role": role, "parts": [{"text": message.get("content", "")}]})
    return contents


class GeminiAdapter(TargetAdapter):
    async def _send(self, request: TargetRequest) -> TargetResponse:
        key = self._get_key()
        headers = {"Content-Type": "application/json"}
        if key:
            headers["x-goog-api-key"] = key

        if "models/" in self.endpoint:
            url = self.endpoint
        else:
            url = f"{self.endpoint.rstrip('/')}/v1beta/models/{self.model}:generateContent"

        payload = {
            "contents": _messages_to_gemini_contents(request.messages),
            "generationConfig": {
                "temperature": request.temperature,
                "maxOutputTokens": request.max_tokens,
            },
        }

        async with self._client() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        candidates = data.get("candidates", [])
        parts = candidates[0].get("content", {}).get("parts", []) if candidates else []

        text = "".join(part.get("text", "") for part in parts if "text" in part)
        tool_calls = [part.get("functionCall") for part in parts if "functionCall" in part]

        return TargetResponse(
            response=text,
            tool_calls=[call for call in tool_calls if call],
            metadata={
                "provider": "gemini",
                "status": response.status_code,
            },
                                    )
