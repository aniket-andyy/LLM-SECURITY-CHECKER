"""Shared Pydantic schemas.

These models are deliberately defensive: many fields have defaults because
LLM output can be malformed or incomplete. Validation still happens at the
boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DISCLOSURE = "disclosure"
    AGENCY = "agency"
    ADAPTIVE = "adaptive"


class AttackSuccessResult(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILURE = "FAILURE"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    NEW = "NEW"
    DUPLICATE = "DUPLICATE"
    RECURRENCE = "RECURRENCE"
    REGRESSION = "REGRESSION"
    FIXED = "FIXED"
    UNRELATED = "UNRELATED"


class DisclosureStatus(str, Enum):
    REQUESTED = "REQUESTED"
    AVAILABLE = "AVAILABLE"
    REVEALED = "REVEALED"
    AUTHORIZED = "AUTHORIZED"
    SENSITIVE = "SENSITIVE"
    VERIFIED = "VERIFIED"


class Attack(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    category: AttackCategory = AttackCategory.PROMPT_INJECTION
    technique: str = "direct"
    objective: str = ""
    prompt: str = ""
    context: Dict[str, Any] = Field(default_factory=dict)
    iteration: int = 0


class AttackSuccessAssessment(BaseModel):
    attack_id: str = ""
    result: AttackSuccessResult = AttackSuccessResult.AMBIGUOUS
    confidence: Confidence = Confidence.LOW
    rationale: str = ""
    evidence_ids: List[str] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    category: str = "generic"
    title: str = ""
    root_cause: str = ""
    trigger: str = ""
    attack_pattern: str = ""
    affected_component: str = "target_model"
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    evidence: List[str] = Field(default_factory=list)
    related_attacks: List[str] = Field(default_factory=list)
    classification: FindingStatus = FindingStatus.NEW
    disclosure_status: Optional[DisclosureStatus] = None


class VulnerabilityRecord(BaseModel):
    finding_id: str = ""
    fingerprint: str = ""
    classification: FindingStatus = FindingStatus.NEW
    first_seen: str = Field(default_factory=utcnow)
    last_seen: str = Field(default_factory=utcnow)
    occurrences: int = 1


class BlastRadius(BaseModel):
    finding_id: str = ""
    demonstrated_impact: List[str] = Field(default_factory=list)
    theoretical_impact: List[str] = Field(default_factory=list)
    data_exposure: str = "none"
    tool_access: str = "none"
    permission_level: str = "none"
    external_actions: bool = False
    reversibility: str = "unknown"
    business_impact: str = "unknown"
    severity_adjustment: str = "none"


class DefenseEvaluation(BaseModel):
    summary: str = ""
    metrics: Dict[str, Any] = Field(default_factory=dict)
    improvement: bool = False
    rationale: str = ""


class FinalReport(BaseModel):
    scan_id: str = ""
    generated_at: str = Field(default_factory=utcnow)
    executive_summary: str = ""
    security_score: int = 100
    overall_risk: str = "LOW"
    findings: List[SecurityFinding] = Field(default_factory=list)
    critical_findings: List[SecurityFinding] = Field(default_factory=list)
    high_findings: List[SecurityFinding] = Field(default_factory=list)
    medium_findings: List[SecurityFinding] = Field(default_factory=list)
    low_findings: List[SecurityFinding] = Field(default_factory=list)
    attack_statistics: Dict[str, Any] = Field(default_factory=dict)
    prompt_injection_results: Dict[str, Any] = Field(default_factory=dict)
    sensitive_data_results: Dict[str, Any] = Field(default_factory=dict)
    agency_results: Dict[str, Any] = Field(default_factory=dict)
    blast_radius: List[BlastRadius] = Field(default_factory=list)
    defense_effectiveness: Optional[Dict[str, Any]] = None
    false_positives: List[str] = Field(default_factory=list)
    potential_false_negatives: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
