"""AEGIS orchestration pipeline."""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime
from importlib import import_module
from uuid import uuid4

from aegis.attacks.base import BaseAttackModule
from aegis.attacks.llm01_prompt_inject import PromptInjectionModule
from aegis.config import load_config
from aegis.evaluation.scorer import RuleBasedScorer
from aegis.interfaces.attack import AttackModule
from aegis.interfaces.scorer import Scorer
from aegis.models import (
    EvaluationResult,
    Finding,
    OWASPCategoryResult,
    SecurityReport,
    Severity,
)
from aegis.testbed.agent import DefaultAgent

logger = logging.getLogger(__name__)

_RECOMMENDATIONS_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "Block high-risk tool invocations with strict policy gating.",
    Severity.HIGH: "Strengthen instruction boundary checks and output filtering.",
    Severity.MEDIUM: "Tighten tool parameter validation and monitoring coverage.",
    Severity.LOW: "Track low-risk findings and add regression tests.",
}


class AEGISOrchestrator:
    """Run attacks against the testbed agent and produce security reports."""

    def __init__(self, config_path: str | None = None) -> None:
        self.config = load_config(config_path)
        self.agent = DefaultAgent(config=dict(self.config["testbed"]))
        self.attacks = self._load_attacks()
        self.scorers = self._load_scorers()

    def run_baseline(self) -> SecurityReport:
        """Run all loaded attacks with no active defense."""
        return self._run(attacks=self.attacks, defense_name=None)

    def run_with_defense(self, defense_name: str) -> SecurityReport:
        """Run all loaded attacks with one defense enabled."""
        self.agent.enable_defense(defense_name, {"enabled": True})
        try:
            return self._run(attacks=self.attacks, defense_name=defense_name)
        finally:
            self.agent.disable_defense(defense_name)

    def run_attack_module(self, module_name: str) -> SecurityReport:
        """Run a single attack module by module name."""
        attack = self._load_single_attack(module_name)
        return self._run(attacks=[attack], defense_name=None)

    def run_full_matrix(self) -> dict[str, SecurityReport]:
        """Run baseline + each configured defense."""
        reports: dict[str, SecurityReport] = {"baseline": self.run_baseline()}
        for defense_name in self.config["defenses"]["available"]:
            reports[defense_name] = self.run_with_defense(str(defense_name))

        baseline_rate = reports["baseline"].attack_success_rate
        for key, report in reports.items():
            if key == "baseline":
                continue
            report.defense_comparison = {
                "baseline_attack_success_rate": baseline_rate,
                "defense_attack_success_rate": report.attack_success_rate,
                "delta_attack_success_rate": report.attack_success_rate - baseline_rate,
            }
        return reports

    def _run(
        self,
        attacks: list[AttackModule],
        defense_name: str | None,
    ) -> SecurityReport:
        eval_results: list[EvaluationResult] = []
        scorer = self.scorers[0]

        for attack in attacks:
            attack.generate_payloads(self.agent.get_config())
            results = attack.execute(self.agent)
            for result in results:
                eval_results.append(scorer.evaluate(result))

        return self._build_report(eval_results, defense_name=defense_name)

    def _build_report(
        self,
        eval_results: list[EvaluationResult],
        defense_name: str | None,
    ) -> SecurityReport:
        grouped: dict[str, list[EvaluationResult]] = defaultdict(list)
        findings: list[Finding] = []
        recommendations: set[str] = set()

        for eval_result in eval_results:
            grouped[eval_result.owasp_id].append(eval_result)
            if not eval_result.success:
                continue

            payload = eval_result.attack_result.payload
            evidence = eval_result.indicators or [eval_result.attack_result.response.final_output]
            finding = Finding(
                title=f"{payload.owasp_id} attack succeeded ({payload.id})",
                owasp_id=payload.owasp_id,
                atlas_technique=payload.atlas_technique,
                severity=payload.severity,
                description=eval_result.explanation,
                evidence=evidence[:5],
                recommendation=_RECOMMENDATIONS_BY_SEVERITY[payload.severity],
            )
            findings.append(finding)
            recommendations.add(_RECOMMENDATIONS_BY_SEVERITY[payload.severity])

        results_by_owasp: dict[str, OWASPCategoryResult] = {}
        for owasp_id, items in grouped.items():
            total = len(items)
            successful = sum(1 for item in items if item.success)
            attack_success_rate = successful / total if total else 0.0
            category_name = items[0].attack_result.payload.category if items else owasp_id
            category_findings = [finding for finding in findings if finding.owasp_id == owasp_id]
            results_by_owasp[owasp_id] = OWASPCategoryResult(
                owasp_id=owasp_id,
                category_name=category_name,
                total_attacks=total,
                successful_attacks=successful,
                attack_success_rate=attack_success_rate,
                findings=category_findings,
            )

        total_attacks = len(eval_results)
        total_successful = sum(1 for item in eval_results if item.success)
        attack_success_rate = (total_successful / total_attacks) if total_attacks else 0.0
        if not recommendations:
            recommendations.add("No successful attacks detected; maintain current controls.")

        defense_comparison = None
        if defense_name is not None:
            defense_comparison = {"defense_name": defense_name}

        return SecurityReport(
            report_id=f"report-{uuid4()}",
            generated_at=datetime.now(UTC),
            testbed_config=self.agent.get_config(),
            total_attacks=total_attacks,
            total_successful=total_successful,
            attack_success_rate=attack_success_rate,
            results_by_owasp=results_by_owasp,
            defense_comparison=defense_comparison,
            findings=findings,
            recommendations=sorted(recommendations),
        )

    def _load_attacks(self) -> list[AttackModule]:
        attack_names = self.config["attacks"]["modules"]
        attacks: list[AttackModule] = []
        for module_name in attack_names:
            try:
                attacks.append(self._load_single_attack(str(module_name)))
            except Exception as exc:
                logger.warning("Skipping unavailable attack module '%s': %s", module_name, exc)

        if not attacks:
            logger.warning("No configured attack modules loaded; using PromptInjectionModule fallback")
            attacks.append(PromptInjectionModule())
        return attacks

    def _load_single_attack(self, module_name: str) -> AttackModule:
        module = import_module(f"aegis.attacks.{module_name}")
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseAttackModule)
                and obj is not BaseAttackModule
                and getattr(obj, "name", "") == module_name
            ):
                return obj()

        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseAttackModule)
                and obj is not BaseAttackModule
            ):
                return obj()

        raise ValueError(f"No attack class found in module '{module_name}'")

    def _load_scorers(self) -> list[Scorer]:
        scorer_names = [str(name) for name in self.config["evaluation"]["scorers"]]
        scorers: list[Scorer] = []
        for name in scorer_names:
            if name == "rule_based":
                scorers.append(RuleBasedScorer())
            else:
                logger.warning("Skipping unavailable scorer '%s'", name)
        if not scorers:
            scorers.append(RuleBasedScorer())
        return scorers
