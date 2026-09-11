"""Redaction utilities for logs, reports, and error messages."""

from __future__ import annotations

import re
from typing import Any, Dict, List

REDACTION_PATTERNS = [
    (
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth(?:orization)?|token|secret|password)\b\s*[:=]\s*[^\s,;\"']+"
        ),
        "[REDACTED_CREDENTIAL]",
    ),
    (
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{8,}\b"),
        "[REDACTED_BEARER_TOKEN]",
    ),
    (
        re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
        "[REDACTED_OPENAI_STYLE_KEY]",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "[REDACTED_SSN]",
    ),
]

SENSITIVE_DICT_KEYS = {
    "api_key",
    "apikey",
    "key",
    "token",
    "access_token",
    "authorization",
    "password",
    "secret",
}


def redact_text(value: str) -> str:
    """Redact obvious secrets and PII from a string."""
    if not isinstance(value, str):
        return value
    out = value
    for pattern, replacement in REDACTION_PATTERNS:
        out = pattern.sub(replacement, out)
    return out[:20_000]


def redact_dict(value: Any) -> Any:
    """Recursively redact dictionaries/lists for safe reporting."""
    if isinstance(value, dict):
        clean: Dict[str, Any] = {}
        for k, v in value.items():
            if str(k).lower() in SENSITIVE_DICT_KEYS:
                clean[k] = "[REDACTED]"
            else:
                clean[k] = redact_dict(v)
        return clean

    if isinstance(value, list):
        return [redact_dict(item) for item in value]

    if isinstance(value, str):
        return redact_text(value)

    return value
