"""Generic custom HTTP target adapter."""

from __future__ import annotations

import httpx

from app.target.base import TargetAdapter, TargetRequest, TargetResponse


class CustomHTTPAdapter(TargetAdapter):
    async def _send(self, request: TargetRequest) -> TargetResponse:
        headers = dict(self.extra.get("headers", {}))
        key = self._get_key()
        auth_header = self.extra.get("auth_header", "Authorization")
        if key:
            headers[auth_header] = f"Bearer {key}"

        payload = {
            "model": self.model,
            "messages": request.messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        async with self._client() as client:
            response = await client.post(self.endpoint, headers=headers, json=payload)
            response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            data = {"raw_text": response.text}

        if isinstance(data, str):
            content = data
        elif isinstance(data, dict):
            content = (
                data.get("response")
                or data.get("output")
                or data.get("text")
                or data.get("raw_text")
                or ""
            )
        else:
            content = str(data)

        tool_calls = []
        if isinstance(data, dict):
            tool_calls = data.get("tool_calls", []) or []

        return TargetResponse(
            response=str(content),
            tool_calls=tool_calls,
            metadata={"provider": "custom", "status": response.status_code},
        )
