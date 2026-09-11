"""Final report generation."""

from __future__ import annotations

from typing import Any, Dict, List

from app.privacy.redaction import redact_dict
from app.reports.scorer import compute_security_score
from app.schemas import (
    BlastRadius,
    Confidence,
    FinalReport,
    SecurityFinding,
    Severity,
)
from app.security.metrics import compute_metrics


def _category_stats(
    attack_history: List[Dict[str, Any]],
    findings: List[SecurityFinding],
    categories: List[str],
) -> Dict[str, Any]:
    attacks = 0
    successes = 0

    for item in attack_history:
        attack = item.get("attack", {})
        if attack.get("category") in categories:
            attacks += 1
            if item.get("result") in {"SUCCESS", "PARTIAL_SUCCESS"}:
                successes += 1

    finding_count = len([f for f in findings if f.category in categories])

    return {
        "attacks": attacks,
        "successes": successes,
        "findings": finding_count,
    }


def _build_recommendations(findings: List[SecurityFinding]) -> List[str]:
    recommendations = set()

    for finding in findings:
        if finding.category == "prompt_injection":
            recommendations.add(
                "Enforce instruction hierarchy and isolate untrusted content from system instructions."
            )
        elif finding.category == "sensitive_information_disclosure":
            recommendations.add(
                "Apply deterministic output filtering for secrets, PII, and system configuration."
            )
        elif finding.category == "unauthorized_action":
            recommendations.add(
                "Enforce explicit tool authorization and require confirmation for destructive actions."
            )

    recommendations.add("Run authorized red-team evaluations after each model or policy change.")
    return sorted(recommendations)


async def generate_report(state: Dict[str, Any], services: Any) -> Dict[str, Any]:
    findings_raw = state.get("findings", [])
    findings = [SecurityFinding.model_validate(item) for item in findings_raw]

    attack_history = state.get("attack_history", [])
    metrics = compute_metrics(attack_history, findings_raw)

    score, risk = compute_security_score(metrics, findings)

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    low = [f for f in findings if f.severity == Severity.LOW]

    false_positives = [f.id for f in findings if f.confidence == Confidence.LOW]

    potential_false_negatives = [
        item.get("attack", {}).get("id", "")
        for item in attack_history
        if item.get("result") in {"AMBIGUOUS", "FAILURE"}
    ]
    potential_false_negatives = [x for x in potential_false_negatives if x]

    prompt_injection_results = _category_stats(
        attack_history,
        findings,
        ["prompt_injection"],
    )
    sensitive_data_results = _category_stats(
        attack_history,
        findings,
        ["disclosure", "sensitive_information_disclosure"],
    )
    agency_results = _category_stats(
        attack_history,
        findings,
        ["agency", "unauthorized_action"],
    )

    blast_radiuses = [
        BlastRadius.model_validate(item) for item in state.get("blast_radiuses", [])
    ]

    executive_summary = (
        f"Automated evaluation completed {metrics.get('total_attacks', 0)} attacks. "
        f"{len(findings)} findings were recorded. "
        f"Security score: {score}/100. Overall risk: {risk}. "
        "All conclusions are based on ephemeral evidence collected during this scan."
    )

    report = FinalReport(
        scan_id=state.get("scan_id", ""),
        executive_summary=executive_summary,
        security_score=score,
        overall_risk=risk,
        findings=findings,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        attack_statistics=metrics,
        prompt_injection_results=prompt_injection_results,
        sensitive_data_results=sensitive_data_results,
        agency_results=agency_results,
        blast_radius=blast_radiuses,
        defense_effectiveness=state.get("defense_evaluation"),
        false_positives=false_positives,
        potential_false_negatives=potential_false_negatives,
        recommendations=_build_recommendations(findings),
        limitations=[
            "LLM-based analysis can miss novel attack classes.",
            "Target responses are untrusted and may be deceptive.",
            "This scan is ephemeral and does not store customer history.",
            "Defense comparison is limited unless paired baseline metrics are supplied.",
        ],
    )

    return redact_dict(report.model_dump())
