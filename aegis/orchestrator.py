"""AEGIS orchestration pipeline."""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from uuid import uuid4

from aegis.attacks.base import BaseAttackModule
from aegis.attacks.llm01_prompt_inject import PromptInjectionModule
from aegis.config import load_config
from aegis.evaluation.pipeline import EvaluationPipeline
from aegis.evaluation.scorer import RuleBasedScorer
from aegis.interfaces.attack import AttackModule
from aegis.interfaces.scorer import Scorer
from aegis.models import (
    AttackResult,
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

    # ------------------------------------------------------------------
    # Public API — high-level convenience methods
    # ------------------------------------------------------------------

    def run_baseline(self) -> SecurityReport:
        """Run all loaded attacks with no active defense."""
        results_path = self.run_attacks(defense_name=None)
        return self.score_results(results_path, defense_name=None)

    def run_with_defense(self, defense_name: str) -> SecurityReport:
        """Run all loaded attacks with one defense enabled."""
        self.agent.enable_defense(defense_name, {"enabled": True})
        try:
            results_path = self.run_attacks(defense_name=defense_name)
            return self.score_results(results_path, defense_name=defense_name)
        finally:
            self.agent.disable_defense(defense_name)

    def run_attack_module(self, module_name: str) -> SecurityReport:
        """Run a single attack module by module name."""
        attack = self._load_single_attack(module_name)
        results_path = self.run_attacks(attacks=[attack], defense_name=None)
        return self.score_results(results_path, defense_name=None)

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

    # ------------------------------------------------------------------
    # Decoupled phases: attack → disk → score
    # ------------------------------------------------------------------

    def run_attacks(
        self,
        attacks: list[AttackModule] | None = None,
        defense_name: str | None = None,
    ) -> Path:
        """Execute attacks, save results to JSONL, return the file path."""
        if attacks is None:
            attacks = self.attacks

        run_id = str(uuid4())
        output_dir = Path(
            self.config["reporting"].get("output_dir", "./reports")
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        results_path = output_dir / f"attack_results_{run_id}.jsonl"

        count = 0
        with results_path.open("w", encoding="utf-8") as fh:
            for attack in attacks:
                attack.generate_payloads(self.agent.get_config())
                results = attack.execute(self.agent)
                for result in results:
                    fh.write(result.model_dump_json() + "\n")
                    count += 1

        logger.info(
            "Saved %d attack results to %s (run_id=%s)", count, results_path, run_id
        )
        return results_path

    def score_results(
        self,
        results_path: str | Path,
        defense_name: str | None = None,
    ) -> SecurityReport:
        """Load AttackResults from JSONL, score with pipeline, build report."""
        results_path = Path(results_path)
        attack_results: list[AttackResult] = []
        with results_path.open("r", encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    attack_results.append(AttackResult.model_validate_json(stripped))
                except Exception as exc:
                    logger.warning(
                        "Skipping invalid JSONL at %s:%d: %s", results_path, line_num, exc
                    )

        pipeline = EvaluationPipeline(scorers=self.scorers)
        eval_results = pipeline.evaluate(attack_results)
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
            elif name == "llm_judge":
                scorers.append(self._build_llm_judge_scorer())
            else:
                logger.warning("Skipping unavailable scorer '%s'", name)
        if not scorers:
            scorers.append(RuleBasedScorer())
        return scorers

    def _build_llm_judge_scorer(self) -> Scorer:
        from aegis.evaluation.llm_judge import LLMJudgeScorer

        judge_model = str(self.config["evaluation"].get("judge_model", "qwen3:1.7b"))
        base_url = str(
            self.config["testbed"]["provider"].get(
                "ollama_base_url", "http://localhost:11434"
            )
        )
        return LLMJudgeScorer(judge_model=judge_model, base_url=base_url)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=None, help="Config YAML path")
    common.add_argument("-o", "--output", default=None, help="Output file path")

    parser = argparse.ArgumentParser(
        description="AEGIS Orchestrator",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("scan", parents=[common], help="Run baseline (attack + score)")
    sub.add_parser("attack", parents=[common], help="Run attacks only, save to JSONL")
    score_cmd = sub.add_parser("score", parents=[common], help="Score saved results")
    score_cmd.add_argument("results", help="Path to attack results JSONL")

    args = parser.parse_args()
    orch = AEGISOrchestrator(config_path=args.config)

    if args.command == "attack":
        path = orch.run_attacks()
        print(f"Attack results saved to {path}")
    elif args.command == "score":
        report = orch.score_results(args.results)
        output_text = json.dumps(report.model_dump(mode="json"), indent=2)
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_text, encoding="utf-8")
            print(f"Report written to {out_path}")
        else:
            print(output_text)
    else:  # scan or no command → baseline
        report = orch.run_baseline()
        output_text = json.dumps(report.model_dump(mode="json"), indent=2)
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_text, encoding="utf-8")
            print(f"Report written to {out_path}")
        else:
            print(output_text)
