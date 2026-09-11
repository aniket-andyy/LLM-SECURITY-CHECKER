"""Cleanup helpers for ephemeral scan state."""

from __future__ import annotations

from typing import Any, MutableMapping


def best_effort_clear_mapping(mapping: MutableMapping[str, Any]) -> None:
    """Best-effort clearing of in-memory data.

    Python does not guarantee secure memory zeroization, but we can remove
    references promptly.
    """
    for key in list(mapping.keys()):
        mapping.pop(key, None)
