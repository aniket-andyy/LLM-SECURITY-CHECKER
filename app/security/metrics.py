"""Deterministic scan metrics.

The LLM must never invent these values.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _get_field(obj: Any, field: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(field, default)
    return getattr(obj, field, default)


def _result_from_history_item(item: Dict[str, Any]) -> str:
    if item.get("result"):
        return str(item.get("result"))
    assessment = item.get("assessment", {})
    return str(assessment.get("result", "AMBIGUOUS"))


def compute_metrics(
    attack_history: List[Dict[str, Any]],
    findings: List[Any] | None = None,
    false_positives: int = 0,
    false_negatives: int = 0,
) -> Dict[str, Any]:
    attack_history = attack_history or []
    findings = findings or []

    total = len(attack_history)
    success = 0
    partial = 0
    failure = 0
    ambiguous = 0

    for item in attack_history:
        result = _result_from_history_item(item)
        if result == "SUCCESS":
            success += 1
        elif result == "PARTIAL_SUCCESS":
            partial += 1
        elif result == "FAILURE":
            failure += 1
        else:
            ambiguous += 1

    critical_findings = 0
    high_findings = 0

    for finding in findings:
        severity = str(_get_field(finding, "severity", "INFO")).upper()
        if severity == "CRITICAL":
            critical_findings += 1
        elif severity == "HIGH":
            high_findings += 1

    checked = max(total, 1)

    return {
        "total_attacks": total,
        "success": success,
        "partial_success": partial,
        "failure": failure,
        "ambiguous": ambiguous,
        "attack_success_rate": success / checked,
        "partial_success_rate": partial / checked,
        "failure_rate": failure / checked,
        "ambiguous_rate": ambiguous / checked,
        "false_positive_rate": false_positives / max(len(findings), 1),
        "false_negative_rate": false_negatives / max(total, 1),
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "critical_confirmed": critical_findings > 0,
    }


def defense_improvement(before: Dict[str, Any], after: Dict[str, Any]) -> float:
    before_asr = float(before.get("attack_success_rate", 0.0))
    after_asr = float(after.get("attack_success_rate", 0.0))
    return before_asr - after_asr
