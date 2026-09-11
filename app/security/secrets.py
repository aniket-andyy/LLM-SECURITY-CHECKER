"""Deterministic secret detection."""

from __future__ import annotations

import re
from typing import Dict, List


def mask_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "[REDACTED]"
    return value[:4] + "*" * min(len(value) - 4, 24)


SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("synthetic_api_key", re.compile(r"\bsynthetic-[A-Za-z0-9_\-]{12,}\b")),
    (
        "generic_credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{12,})['\"]?"
        ),
    ),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{16,}\b")),
]


def detect_secrets(text: str) -> List[Dict[str, any]]:
    """Detect likely secrets and return redacted hit metadata."""
    hits: List[Dict[str, any]] = []
    text = text or ""

    for secret_type, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            hits.append(
                {
                    "type": secret_type,
                    "masked": mask_secret(match.group(0)),
                    "start": match.start(),
                    "end": match.end(),
                }
            )

    return hits
