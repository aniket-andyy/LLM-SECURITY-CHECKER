"""LangGraph state definition.

This state must never contain secrets.
"""

from __future__ import annotations

from typing import Any, Dict, List, TypedDict


class ScanState(TypedDict, total=False):
    scan_id: str
    target_metadata: Dict[str, Any]
    scan_config: Dict[str, Any]

    current_phase: str
    iteration: int

    current_attack: Dict[str, Any]
    attack_history: List[Dict[str, Any]]
    target_responses: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]

    findings: List[Dict[str, Any]]
    vulnerability_memory: List[Dict[str, Any]]
    blast_radiuses: List[Dict[str, Any]]

    metrics: Dict[str, Any]
    defense_evaluation: Dict[str, Any]
    errors: List[str]

    should_continue: bool
    last_attack_success: str
    last_finding_id: str
    stop_reason: str

    report: Dict[str, Any]
