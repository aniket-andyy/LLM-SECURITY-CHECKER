"""Lightweight in-memory hashing embeddings.

No external vector database is used. This exists only for temporary
similarity reasoning during an active scan.
"""

from __future__ import annotations

import hashlib
import math
from typing import List

from app.security.similarity import token_set


class HashingEmbedder:
    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dim

        for token in token_set(text):
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            idx = int(digest, 16) % self.dim
            sign = 1.0 if int(digest[-1], 16) % 2 == 0 else -1.0
            vec[idx] += sign

        norm = math.sqrt(sum(x * x for x in vec))
        if norm == 0:
            return vec

        return [x / norm for x in vec]

    def cosine(self, a: str, b: str) -> float:
        vec_a = self.embed(a)
        vec_b = self.embed(b)
        dot = sum(x * y for x, y in zip(vec_a, vec_b))
        return dot
