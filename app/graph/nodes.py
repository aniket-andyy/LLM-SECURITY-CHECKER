"""LangGraph node implementations."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from uuid import uuid4

import yaml

from app.agents.adaptive_attack import AdaptiveAttackAgent
from app.agents.agency import AgencyEvaluator
from app.agents.attack_success import AttackSuccessEvaluator
from app.agents.blast_radius import BlastRadiusAssessor
from app.agents.defense_evaluation import DefenseEvaluator
from app.agents.disclosure import DisclosureEvaluator
from app.agents.prompt_injection import PromptInjectionAgent
from app.agents.vulnerability_memory import VulnerabilityMemoryAgent
from app.memory.vulnerability_memory import EphemeralVulnerabilityMemory
from app.models.model_router import ModelRouter
from app.privacy.secret_manager import EphemeralSecretManager
from app.reports.generator import generate_report
from app.schemas import Attack, AttackSuccessResult, Evidence, SecurityFinding
from app.security.evidence import EvidenceEngine
from app.security.metrics import compute_metrics
from app.security.permissions import PermissionEngine
from app.target.base import TargetConfig, TargetRequest, TargetResponse
from app.target import create_target_adapter

SUCCESS_RESULTS = {
    AttackSuccessResult.SUCCESS.value,
    AttackSuccessResult.PARTIAL_SUCCESS.value,
}


def load_security_profiles(path: str = "configs/security_profiles.yaml") -> Dict[str, Any]:
    try:
        return yaml.safe_load(Path(path).read_text()) or {}
    except Exception:
        return {
            "quick": {
                "max_attacks": 5,
                "max_iterations": 5,
                "timeout": 20,
                "max_errors": 3,
                "categories": ["prompt_injection", "disclosure"],
            }
        }


class ScanServices:
    """Session-scoped services.

    This object is intentionally not placed in LangGraph state.
    """

    def __init__(
        self,
        target_config: TargetConfig,
        scan_config: Dict[str, Any],
        secret_manager: EphemeralSecretManager,
        model_router: ModelRouter | None = None,
    ) -> None:
        self.target_config = target_config
        self.scan_config = scan_config
        self.secret_manager = secret_manager
        self.model_router = model_router or ModelRouter.from_default()

        self.target_adapter = create_target_adapter(target_config, secret_manager)
        self.permission_engine = PermissionEngine.default()
        self.evidence_engine = EvidenceEngine(self.permission_engine)
        self.memory = EphemeralVulnerabilityMemory()

        self.injection_agent = PromptInjectionAgent(self.model_router)
        self.adaptive_agent = AdaptiveAttackAgent(self.model_router, self.injection_agent)
        self.success_evaluator = AttackSuccessEvaluator(self.model_router)
        self.disclosure_evaluator = DisclosureEvaluator(self.model_router)
        self.agency_evaluator = AgencyEvaluator(self.model_router, self.permission_engine)
        self.memory_agent = VulnerabilityMemoryAgent(self.memory)
        self.blast_assessor = BlastRadiusAssessor(self.model_router)
        self.defense_evaluator = DefenseEvaluator(self.model_router)

    def cleanup(self) -> None:
        self.secret_manager.clear()
        self.memory.clear()


class GraphNodes:
    def __init__(self, services: ScanServices) -> None:
        self.services = services

    async def initialize_scan(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "scan_id": uuid4().hex,
            "current_phase": "initialized",
            "iteration": 0,
            "attack_history": [],
            "target_responses": [],
            "evidence": [],
            "findings": [],
            "vulnerability_memory": [],
            "blast_radiuses": [],
            "errors": [],
            "metrics": {},
            "should_continue": True,
            "last_attack_success": "",
            "last_finding_id": "",
            "stop_reason": "",
        }

    async def plan_scan(self, state: Dict[str, Any]) -> Dict[str, Any]:
        cfg = dict(state.get("scan_config", {}))
        profiles = load_security_profiles()
        profile_name = cfg.get("profile", "quick")
        profile = profiles.get(profile_name, profiles.get("quick", {}))

        merged = {**profile, **cfg}
        merged.setdefault("max_attacks", 5)
        merged.setdefault("max_iterations", 5)
        merged.setdefault("max_errors", 5)
        merged.setdefault("timeout", 30)
        merged.setdefault("categories", ["prompt_injection"])
        merged.setdefault("stop_on_critical", True)
        merged.setdefault("adaptive", True)
        merged.setdefault("defense_comparison", False)

        return {
            "scan_config": merged,
            "current_phase": "planned",
        }

    async def generate_attack(self, state: Dict[str, Any]) -> Dict[str, Any]:
        cfg = state.get("scan_config", {})
        categories = cfg.get("categories", ["prompt_injection"])
        iteration = int(state.get("iteration", 0)) + 1

        category = categories[(iteration - 1) % len(categories)]

        attack = await self.services.adaptive_agent.next_attack(
            iteration=iteration,
            category=category,
            history=state.get("attack_history", []),
            findings=state.get("findings", []),
        )

        return {
            "current_attack": attack.model_dump(),
            "iteration": iteration,
            "current_phase": "attack_generated",
        }

    async def send_attack(self, state: Dict[str, Any]) -> Dict[str, Any]:
        attack = Attack.model_validate(state["current_attack"])
        cfg = state.get("scan_config", {})

        request = TargetRequest(
            messages=[{"role": "user", "content": attack.prompt}],
            max_tokens=int(cfg.get("max_tokens", 512)),
            temperature=0.0,
            metadata={"attack_id": attack.id},
        )

        response = await self.services.target_adapter.send(request)

        target_responses = state.get("target_responses", []) + [
            {
                "attack_id": attack.id,
                "response": response.model_dump(),
            }
        ]

        errors = state.get("errors", []) + response.errors

        return {
            "target_responses": target_responses,
            "errors": errors,
            "current_phase": "attack_sent",
        }

    async def collect_evidence(self, state: Dict[str, Any]) -> Dict[str, Any]:
        attack = Attack.model_validate(state["current_attack"])
        latest = state["target_responses"][-1]
        response = TargetResponse.model_validate(latest["response"])

        evidence = self.services.evidence_engine.collect(attack, response)

        return {
            "evidence": state.get("evidence", []) + [evidence.model_dump()],
            "current_phase": "evidence_collected",
        }

    async def run_deterministic_checks(self, state: Dict[str, Any]) -> Dict[str, Any]:
        # Deterministic checks are already embedded in evidence collection.
        return {"current_phase": "deterministic_checks"}

    async def evaluate_attack_success(self, state: Dict[str, Any]) -> Dict[str, Any]:
        attack = Attack.model_validate(state["current_attack"])
        latest = state["target_responses"][-1]
        response = TargetResponse.model_validate(latest["response"])
        evidence = Evidence.model_validate(state["evidence"][-1])

        assessment = await self.services.success_evaluator.evaluate(
            attack,
            response,
            evidence,
        )

        attack_history = state.get("attack_history", []) + [
            {
                "attack": attack.model_dump(),
                "result": assessment.result.value,
                "assessment": assessment.model_dump(),
            }
        ]

        return {
            "attack_history": attack_history,
            "last_attack_success": assessment.result.value,
            "current_phase": "attack_evaluated",
        }

    async def record_finding(self, state: Dict[str, Any]) -> Dict[str, Any]:
        if state.get("last_attack_success") not in SUCCESS_RESULTS:
            return {
                "last_finding_id": "",
                "current_phase": "no_finding",
            }

        attack = Attack.model_validate(state["current_attack"])
        evidence = Evidence.model_validate(state["evidence"][-1])

        candidates = []

        disclosure = await self.services.disclosure_evaluator.evaluate(attack, evidence)
        agency = await self.services.agency_evaluator.evaluate(attack, evidence)

        if disclosure:
            candidates.append(disclosure)
        if agency:
            candidates.append(agency)

        if not candidates:
            return {
                "last_finding_id": "",
                "current_phase": "finding_not_confirmed",
            }

        findings = list(state.get("findings", []))
        new_ids = []

        for finding in candidates:
            self.services.memory_agent.record(finding)
            findings.append(finding.model_dump())
            new_ids.append(finding.id)

        return {
            "findings": findings,
            "last_finding_id": new_ids[0],
            "current_phase": "finding_recorded",
        }

    async def update_vulnerability_memory(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "vulnerability_memory": self.services.memory.export(),
            "current_phase": "memory_updated",
        }

    async def assess_blast_radius(self, state: Dict[str, Any]) -> Dict[str, Any]:
        finding_id = state.get("last_finding_id", "")
        finding_data = next(
            (item for item in state.get("findings", []) if item.get("id") == finding_id),
            None,
        )

        if not finding_data:
            return {"current_phase": "blast_skipped"}

        finding = SecurityFinding.model_validate(finding_data)
        evidence = Evidence.model_validate(state["evidence"][-1])

        blast = await self.services.blast_assessor.assess(finding, evidence)

        return {
            "blast_radiuses": state.get("blast_radiuses", []) + [blast.model_dump()],
            "current_phase": "blast_radius_assessed",
        }

    async def decide_next_attack(self, state: Dict[str, Any]) -> Dict[str, Any]:
        cfg = state.get("scan_config", {})
        iteration = int(state.get("iteration", 0))

        metrics = compute_metrics(
            state.get("attack_history", []),
            state.get("findings", []),
        )

        should_continue = True
        stop_reason = ""

        max_attacks = int(cfg.get("max_attacks", 5))
        max_errors = int(cfg.get("max_errors", 5))
        stop_on_critical = bool(cfg.get("stop_on_critical", True))

        if iteration >= max_attacks:
            should_continue = False
            stop_reason = "max_attacks_reached"
        elif len(state.get("errors", [])) >= max_errors:
            should_continue = False
            stop_reason = "max_errors_reached"
        elif stop_on_critical and metrics.get("critical_confirmed"):
            should_continue = False
            stop_reason = "critical_vulnerability_confirmed"
        elif not cfg.get("adaptive", True) and iteration >= int(
            cfg.get("max_iterations", max_attacks)
        ):
            should_continue = False
            stop_reason = "max_iterations_reached"

        return {
            "metrics": metrics,
            "should_continue": should_continue,
            "stop_reason": stop_reason,
            "current_phase": "decision",
        }

    async def evaluate_defense(self, state: Dict[str, Any]) -> Dict[str, Any]:
        cfg = state.get("scan_config", {})
        evaluation = await self.services.defense_evaluator.evaluate(
            state.get("metrics", {}),
            state.get("findings", []),
            bool(cfg.get("defense_comparison", False)),
        )

        return {
            "defense_evaluation": evaluation.model_dump(),
            "current_phase": "defense_evaluated",
        }

    async def generate_final_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        report = await generate_report(state, self.services)
        return {
            "report": report,
            "current_phase": "report_generated",
        }

    async def cleanup(self, state: Dict[str, Any]) -> Dict[str, Any]:
        self.services.cleanup()

        return {
            "current_phase": "cleanup",
            "target_responses": [],
            "evidence": [],
            "vulnerability_memory": [],
            "findings": [],
            "attack_history": [],
      }
