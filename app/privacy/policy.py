"""Privacy policy enforcement helpers."""

from __future__ import annotations

from typing import Any, Dict

FORBIDDEN_STATE_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "authorization",
    "password",
    "secret",
}


def assert_no_forbidden_keys(obj: Any, path: str = "$") -> None:
    """Raise if forbidden credential-like keys appear in LangGraph state."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in FORBIDDEN_STATE_KEYS:
                raise ValueError(f"Forbidden key in state: {path}.{key}")
            assert_no_forbidden_keys(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            assert_no_forbidden_keys(item, f"{path}[{idx}]")
