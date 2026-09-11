"""Deterministic similarity / deduplication helpers."""

from __future__ import annotations

import hashlib
import re
from typing import Set


def normalize_text(text: str) -> str:
    text = (text or "").lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return " ".join(text.split())


def token_set(text: str) -> Set[str]:
    return set(normalize_text(text).split())


def jaccard_similarity(a: str, b: str) -> float:
    set_a = token_set(a)
    set_b = token_set(b)

    if not set_a and not set_b:
        return 1.0

    if not set_a or not set_b:
        return 0.0

    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union else 0.0


def fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def is_similar(a: str, b: str, threshold: float = 0.75) -> bool:
    return jaccard_similarity(a, b) >= threshold
