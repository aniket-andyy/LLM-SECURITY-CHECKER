"""Deterministic PII detection."""

from __future__ import annotations

import re
from typing import Dict, List


def mask_pii(value: str) -> str:
    value = value.strip()
    if "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:1]}***@{domain}"
    if len(value) <= 6:
        return "[REDACTED]"
    return value[:2] + "*" * min(len(value) - 4, 16) + value[-2:]


PII_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (
        "phone_number",
        re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ),
]


def detect_pii(text: str) -> List[Dict[str, any]]:
    hits: List[Dict[str, any]] = []
    text = text or ""

    for pii_type, pattern in PII_PATTERNS:
        for match in pattern.finditer(text):
            hits.append(
                {
                    "type": pii_type,
                    "masked": mask_pii(match.group(0)),
                    "start": match.start(),
                    "end": match.end(),
                }
            )

    return hits
