"""Defense effectiveness evaluation."""

from __future__ import annotations

from typing import Any, Dict, List

from app.models.model_router import ModelRole, ModelRouter
from app.schemas import DefenseEvaluation


class DefenseEvaluator:
    def __init__(self, model_router: ModelRouter) -> None:
        self.model_router = model_router

    async def evaluate(
        self,
        metrics: Dict[str, Any],
        findings: List[Any],
        enabled: bool = False,
    ) -> DefenseEvaluation:
        rationale = (
            "No paired baseline/defense scan was supplied, "
            "so improvement cannot be deterministically proven."
        )

        if enabled:
            rationale = (
                "Defense comparison was requested, but this workflow executed a single scan. "
                "Provide before/after metrics for a full deterministic comparison."
            )

        try:
            user = f"""
Metrics:
{metrics}

Findings count:
{len(findings)}

Return JSON fields:
summary, improvement, rationale.
""".strip()

            evaluation = await self.model_router.structured(
                ModelRole.SECURITY_ANALYST,
                DefenseEvaluation,
                system="You are a defense-effectiveness analyst. Return only JSON.",
                user=user,
            )
            evaluation.metrics = metrics
            return evaluation

        except Exception:
            return DefenseEvaluation(
                summary="Defense evaluation limited to deterministic current-scan metrics.",
                metrics=metrics,
                improvement=False,
                rationale=rationale,
            )
