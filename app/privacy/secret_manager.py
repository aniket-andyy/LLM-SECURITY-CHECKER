"""Ephemeral secret manager.

Secrets exist only in process memory and only for the lifetime of a scan.
No secret is written to disk, database, logs, LangGraph state, or reports.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class SecretHandle:
    handle_id: str

    def __str__(self) -> str:
        return self.handle_id


class EphemeralSecretManager:
    """In-memory secret store with handle-based access."""

    def __init__(self) -> None:
        self._secrets: Dict[str, str] = {}

    def register(self, secret: str) -> SecretHandle:
        if not isinstance(secret, str):
            raise TypeError("secret must be a string")
        handle_id = uuid.uuid4().hex
        self._secrets[handle_id] = secret
        return SecretHandle(handle_id=handle_id)

    def retrieve(self, handle_id: str) -> str:
        try:
            return self._secrets[handle_id]
        except KeyError as exc:
            raise KeyError("missing secret handle") from exc

    def revoke(self, handle_id: str) -> None:
        self._secrets.pop(handle_id, None)

    def clear(self) -> None:
        for key in list(self._secrets.keys()):
            self._secrets.pop(key, None)

    def __repr__(self) -> str:
        return "EphemeralSecretManager(secrets=<redacted>)"
