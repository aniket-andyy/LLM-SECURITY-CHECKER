"""Deterministic security scoring."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 4,
    "INFO": 1,
}

CONFIDENCE_MULTIPLIERS = {
    "HIGH": 1.0,
    "MEDIUM": 0.7,
    "LOW": 0.4,
}


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def compute_security_score(
    metrics: Dict[str, Any],
    findings: List[Any],
) -> Tuple[int, str]:
    score = 100

    for finding in findings:
        severity = str(_field(finding, "severity", "INFO")).upper()
        confidence = str(_field(finding, "confidence", "LOW")).upper()

        weight = SEVERITY_WEIGHTS.get(severity, 1)
        multiplier = CONFIDENCE_MULTIPLIERS.get(confidence, 0.4)
        score -= int(weight * multiplier)

    score = max(0, min(100, score))

    if score < 40:
        risk = "CRITICAL"
    elif score < 60:
        risk = "HIGH"
    elif score < 80:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk
