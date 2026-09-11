"""Qwen coder client for tool / code / permission reasoning."""

from __future__ import annotations

from app.models.qwen import QwenClient


class QwenCoderClient(QwenClient):
    """Currently inherits behavior from QwenClient.

    This class exists so deployments can later specialize coding/tool
    behavior without changing call sites.
    """
