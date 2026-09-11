"""Programmatic scan entrypoint."""

from __future__ import annotations

from typing import Any, Dict

from app.graph.nodes import ScanServices
from app.graph.workflow import build_graph
from app.models.model_router import ModelRouter
from app.privacy.secret_manager import EphemeralSecretManager
from app.target.base import TargetConfig


async def run_scan(
    target_config: TargetConfig,
    scan_config: Dict[str, Any],
    secret_manager: EphemeralSecretManager,
    model_router: ModelRouter | None = None,
) -> Dict[str, Any]:
    services = ScanServices(
        target_config=target_config,
        scan_config=scan_config,
        secret_manager=secret_manager,
        model_router=model_router,
    )

    graph = build_graph(services)

    initial_state = {
        "target_metadata": {
            "provider": target_config.provider,
            "model": target_config.model,
            "endpoint": target_config.endpoint,
        },
        "scan_config": scan_config,
    }

    try:
        final_state = await graph.ainvoke(initial_state)
        return final_state.get("report", {})
    finally:
        services.cleanup()
