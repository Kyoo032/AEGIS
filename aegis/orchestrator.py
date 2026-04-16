"""AEGIS orchestration pipeline."""
from __future__ import annotations

import json
import logging
import traceback
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any
from uuid import uuid4

from aegis.attacks.base import BaseAttackModule
from aegis.attacks.llm01_prompt_inject import PromptInjectionModule
from aegis.config import load_config
from aegis.evaluation.pipeline import EvaluationPipeline
from aegis.evaluation.protocol_adapter import ProtocolScorerAdapter
from aegis.evaluation.scorer import RuleBasedScorer
from aegis.evidence.store import EvidenceTraceStore
from aegis.interfaces.attack import AttackModule
from aegis.interfaces.scorer import Scorer
from aegis.interfaces.scorer_protocol import ScorerProtocol
from aegis.models import (
    AttackResult,
    EvaluationResult,
    Finding,
    OWASPCategoryResult,
    SecurityReport,
    Severity,
    TraceRecord,
)
from aegis.reporting.owasp_mapper import get_owasp_info
from aegis.testbed.agent import DefaultAgent

logger = logging.getLogger(__name__)

_RECOMMENDATIONS_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "Block high-risk tool invocations with strict policy gating.",
    Severity.HIGH: "Strengthen instruction boundary checks and output filtering.",
    Severity.MEDIUM: "Tighten tool parameter validation and monitoring coverage.",
    Severity.LOW: "Track low-risk findings and add regression tests.",
    Severity.INFORMATIONAL: "Monitor observed behavior and keep regression coverage up to date.",
}


class AEGISOrchestrator:
    """Run attacks against the testbed agent and produce security reports."""

    def __init__(
        self,
        config_path: str | None = None,
        scorers: list[Scorer] | None = None,
        protocol_scorers: list[ScorerProtocol] | None = None,
    ) -> None:
        self.config = load_config(config_path)
        self.agent = DefaultAgent(config=dict(self.config["testbed"]))
        self.attacks = self._load_attacks()

        configured_scorers: list[Scorer] = (
            list(scorers) if scorers is not None else self._load_scorers()
        )
        if protocol_scorers:
            configured_scorers.extend(ProtocolScorerAdapter(scorer) for scorer in protocol_scorers)
        if not configured_scorers:
            configured_scorers = [RuleBasedScorer()]
        self.scorers = configured_scorers

        self._last_run_errors: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API — high-level convenience methods
    # ------------------------------------------------------------------

    def run_baseline(self) -> SecurityReport:
        """Run all loaded attacks with no active defense."""
        results_path = self.run_attacks(defense_name=None)
        return self.score_results(
            results_path,
            defense_name=None,
            run_errors=list(self._last_run_errors),
        )

    def run_with_defense(self, defense_name: str) -> SecurityReport:
        """Run all loaded attacks with one defense enabled."""
        self.agent.enable_defense(defense_name, {"enabled": True})
        try:
            results_path = self.run_attacks(defense_name=defense_name)
            return self.score_results(
                results_path,
                defense_name=defense_name,
                run_errors=list(self._last_run_errors),
            )
        finally:
            self.agent.disable_defense(defense_name)

    def run_with_defenses(self, defense_names: list[str], label: str | None = None) -> SecurityReport:
        """Run all loaded attacks with multiple defenses enabled simultaneously."""
        normalized = [str(name) for name in defense_names]
        for name in normalized:
            self.agent.enable_defense(name, {"enabled": True})
        defense_label = label or "+".join(normalized)
        try:
            results_path = self.run_attacks(defense_name=defense_label)
            report = self.score_results(
                results_path,
                defense_name=defense_label,
                run_errors=list(self._last_run_errors),
            )
            if report.defense_comparison is None:
                report.defense_comparison = {}
            report.defense_comparison["defenses"] = normalized
            return report
        finally:
            for name in reversed(normalized):
                self.agent.disable_defense(name)

    def run_attack_module(self, module_name: str) -> SecurityReport:
        """Run a single attack module by module name."""
        attack = self._load_single_attack(module_name)
        results_path = self.run_attacks(attacks=[attack], defense_name=None)
        return self.score_results(
            results_path,
            defense_name=None,
            run_errors=list(self._last_run_errors),
        )

    def run_full_matrix(self) -> dict[str, SecurityReport]:
        """Run baseline + each configured defense."""
        reports: dict[str, SecurityReport] = {
            "baseline": self._run_scenario("baseline", self.run_baseline),
        }
        available = self.get_available_defenses()
        for defense_name in available:
            reports[defense_name] = self._run_scenario(
                defense_name,
                lambda d=defense_name: self.run_with_defense(d),
            )

        layered_defaults = [
            ["input_validator", "output_filter", "tool_boundary"],
            ["mcp_integrity", "permission_enforcer"],
            [
                "input_validator",
                "output_filter",
                "tool_boundary",
                "mcp_integrity",
                "permission_enforcer",
            ],
        ]
        layered = self.config["defenses"].get("layered_combinations", layered_defaults)
        for combo in layered:
            if not isinstance(combo, list):
                continue
            names = [str(name) for name in combo if str(name) in available]
            if len(names) < 2:
                continue
            label = "+".join(names)
            reports[label] = self._run_scenario(
                label,
                lambda n=names, lbl=label: self.run_with_defenses(n, label=lbl),
            )

        baseline_rate = reports["baseline"].attack_success_rate if "baseline" in reports else 0.0
        for key, report in reports.items():
            if key == "baseline":
                continue
            delta = report.attack_success_rate - baseline_rate
            report.defense_comparison = {
                **(report.defense_comparison or {}),
                "defense_name": key,
                "baseline_attack_success_rate": baseline_rate,
                "defense_attack_success_rate": report.attack_success_rate,
                "delta_attack_success_rate": delta,
            }
            for finding in report.findings:
                finding.delta_vs_baseline = delta

        matrix_path = self._write_matrix_summary(reports)
        for scenario, report in reports.items():
            report.defense_matrix = {
                "scenario": scenario,
                "summary_path": str(matrix_path),
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
        output_dir = Path(self.config["reporting"].get("output_dir", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        results_path = output_dir / f"attack_results_{run_id}.jsonl"
        trace_store = EvidenceTraceStore(output_dir)
        trace_records: list[TraceRecord] = []

        errors: list[dict[str, Any]] = []
        count = 0
        with results_path.open("w", encoding="utf-8") as fh:
            for attack in attacks:
                module_name = getattr(attack, "name", attack.__class__.__name__)
                try:
                    attack.generate_payloads(self.agent.get_config())
                except Exception as exc:
                    err = _make_error_record(module=module_name, phase="generate_payloads", exc=exc)
                    errors.append(err)
                    logger.exception("Attack payload generation failed for module '%s'", module_name)
                    continue

                try:
                    results = attack.execute(self.agent)
                except Exception as exc:
                    err = _make_error_record(module=module_name, phase="execute", exc=exc)
                    errors.append(err)
                    logger.exception("Attack execution failed for module '%s'", module_name)
                    continue

                for result in results:
                    fh.write(result.model_dump_json() + "\n")
                    trace_records.append(_trace_record_from_attack_result(result))
                    count += 1

        trace_path = trace_store.append_many(run_id=run_id, records=trace_records)
        self._last_run_errors = errors
        logger.info(
            "Saved %d attack results to %s and traces to %s (run_id=%s, errors=%d)",
            count,
            results_path,
            trace_path,
            run_id,
            len(errors),
        )
        return results_path

    def score_results(
        self,
        results_path: str | Path,
        defense_name: str | None = None,
        run_errors: list[dict[str, Any]] | None = None,
    ) -> SecurityReport:
        """Load AttackResults from JSONL, score with pipeline, build report."""
        results_path = Path(results_path)
        errors: list[dict[str, Any]] = list(run_errors or [])

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
                    errors.append(
                        {
                            "module": "jsonl_parser",
                            "phase": "score_results",
                            "status": "error",
                            "error": f"Invalid JSONL at {results_path}:{line_num}: {exc}",
                            "traceback": "",
                        }
                    )

        pipeline = EvaluationPipeline(scorers=self.scorers)
        try:
            eval_results = pipeline.evaluate(attack_results)
        except Exception as exc:
            errors.append(_make_error_record(module="evaluation_pipeline", phase="evaluate", exc=exc))
            logger.exception("Evaluation pipeline failed")
            if getattr(exc, "fatal", False):
                raise
            eval_results = []

        return self._build_report(eval_results, defense_name=defense_name, run_errors=errors)

    def _build_report(
        self,
        eval_results: list[EvaluationResult],
        defense_name: str | None,
        run_errors: list[dict[str, Any]] | None = None,
    ) -> SecurityReport:
        grouped: dict[str, list[EvaluationResult]] = defaultdict(list)
        findings: list[Finding] = []
        recommendations: set[str] = set()
        probe_results: list[dict[str, Any]] = []

        for eval_result in eval_results:
            grouped[eval_result.owasp_id].append(eval_result)

            payload = eval_result.attack_result.payload
            retrieval_trace = eval_result.attack_result.response.retrieval_trace or []
            included_hits = [
                item for item in retrieval_trace if isinstance(item, dict) and bool(item.get("included"))
            ]
            poisoned_included = [
                item for item in included_hits if bool(item.get("is_poisoned"))
            ]
            probe_results.append(
                {
                    "probe_id": payload.id,
                    "module": payload.attack_module,
                    "owasp_id": payload.owasp_id,
                    "owasp_category": payload.category,
                    "passed": not eval_result.success,
                    "success": eval_result.success,
                    "score": eval_result.confidence,
                    "score_method": str(eval_result.scoring_method),
                    "response_snippet": _truncate_text(eval_result.attack_result.response.final_output),
                    "retrieval_trace_count": len(retrieval_trace),
                    "retrieval_included_count": len(included_hits),
                    "retrieval_poisoned_included_count": len(poisoned_included),
                }
            )

            if not eval_result.success:
                continue

            owasp_info = get_owasp_info(payload.owasp_id)
            evidence = eval_result.indicators or [eval_result.attack_result.response.final_output]
            finding = Finding(
                title=f"{payload.owasp_id} attack succeeded ({payload.id})",
                owasp_id=payload.owasp_id,
                owasp_category=owasp_info["name"],
                atlas_technique=payload.atlas_technique,
                mitre_atlas_id=payload.atlas_technique,
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
            default_name = items[0].attack_result.payload.category if items else owasp_id
            category_name = get_owasp_info(owasp_id).get("name") or default_name
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
            run_errors=list(run_errors or []),
            probe_results=probe_results,
        )

    def get_available_attack_modules(self) -> list[str]:
        """Return configured attack module names."""
        return [str(name) for name in self.config["attacks"]["modules"]]

    def get_available_defenses(self) -> list[str]:
        """Return configured defense names."""
        return [str(name) for name in self.config["defenses"]["available"]]

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

        eval_cfg = self.config["evaluation"]
        judge_model = str(eval_cfg.get("judge_model", "qwen3:1.7b"))
        judge_timeout_seconds = float(eval_cfg.get("judge_timeout_seconds", 30))
        judge_max_retries = int(eval_cfg.get("judge_max_retries", 1))
        judge_num_predict = int(eval_cfg.get("judge_num_predict", 64))
        judge_keep_alive = str(eval_cfg.get("judge_keep_alive", "15m"))
        judge_hard_fail = bool(eval_cfg.get("judge_hard_fail", True))
        base_url = str(
            self.config["testbed"]["provider"].get(
                "ollama_base_url", "http://localhost:11434"
            )
        )
        return LLMJudgeScorer(
            judge_model=judge_model,
            base_url=base_url,
            timeout_seconds=judge_timeout_seconds,
            max_retries=judge_max_retries,
            num_predict=judge_num_predict,
            keep_alive=judge_keep_alive,
            hard_fail=judge_hard_fail,
        )

    def _run_scenario(self, name: str, runner: Callable[[], SecurityReport]) -> SecurityReport:
        """Run one scenario and never raise, returning an error report on failure."""
        try:
            return runner()
        except Exception as exc:
            if getattr(exc, "fatal", False):
                raise
            logger.exception("Scenario '%s' failed", name)
            error = _make_error_record(module=name, phase="scenario", exc=exc)
            return self._build_empty_report(defense_name=name if name != "baseline" else None, run_errors=[error])

    def _build_empty_report(
        self,
        defense_name: str | None,
        run_errors: list[dict[str, Any]],
    ) -> SecurityReport:
        defense_comparison = None
        if defense_name is not None:
            defense_comparison = {"defense_name": defense_name}

        return SecurityReport(
            report_id=f"report-{uuid4()}",
            generated_at=datetime.now(UTC),
            testbed_config=self.agent.get_config(),
            total_attacks=0,
            total_successful=0,
            attack_success_rate=0.0,
            results_by_owasp={},
            defense_comparison=defense_comparison,
            findings=[],
            recommendations=["Run failed; inspect run_errors for details."],
            run_errors=run_errors,
            probe_results=[],
        )

    def _write_matrix_summary(self, reports: dict[str, SecurityReport]) -> Path:
        output_dir = Path(self.config["reporting"].get("output_dir", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = output_dir / f"day89_defense_matrix_{timestamp}.json"

        matrix: dict[str, Any] = {
            "generated_at": datetime.now(UTC).isoformat(),
            "baseline": reports["baseline"].attack_success_rate if "baseline" in reports else 0.0,
            "scenarios": {},
            "errors": [],
        }
        baseline_rate = float(matrix["baseline"])
        for name, report in reports.items():
            scenario_errors = [
                {
                    "scenario": name,
                    **error,
                }
                for error in report.run_errors
            ]
            matrix["errors"].extend(scenario_errors)
            matrix["scenarios"][name] = {
                "total_attacks": report.total_attacks,
                "total_successful": report.total_successful,
                "attack_success_rate": report.attack_success_rate,
                "delta_vs_baseline": report.attack_success_rate - baseline_rate,
                "errors": report.run_errors,
                "probe_results": report.probe_results,
            }

        path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
        logger.info("Wrote defense matrix summary to %s", path)
        return path


def _make_error_record(module: str, phase: str, exc: Exception) -> dict[str, Any]:
    return {
        "module": module,
        "phase": phase,
        "status": "error",
        "error": str(exc),
        "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    }


def _trace_record_from_attack_result(result: AttackResult) -> TraceRecord:
    payload = result.payload
    response = result.response
    return TraceRecord(
        campaign_id=result.run_id,
        turn_id=payload.id,
        turn_index=_metadata_int(payload.metadata.get("turn_index"), default=0),
        timestamp=result.timestamp,
        target_fingerprint=response.agent_profile,
        context_source=payload.metadata.get("context_source"),
        delegated_identity=payload.metadata.get("delegated_identity"),
        peer_message_meta=payload.metadata.get("peer_message_meta"),
        approval_summary=payload.metadata.get("approval_summary"),
        actual_action=payload.metadata.get("actual_action"),
        tool_calls=[tool.model_dump(mode="json") for tool in response.tool_calls],
        prompts=list(payload.messages),
        responses=list(response.messages),
        context={
            "payload_id": payload.id,
            "attack_module": payload.attack_module,
            "injected_context": payload.injected_context,
        },
        fixture_state=payload.metadata.get("fixture_state"),
        defense_decisions=(
            [{"defense": response.defense_active, "decision": "active"}]
            if response.defense_active
            else None
        ),
    )


def _metadata_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate_text(text: str, max_len: int = 220) -> str:
    normalized = " ".join(str(text).split())
    if len(normalized) <= max_len:
        return normalized
    return normalized[: max_len - 3] + "..."


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
    else:  # scan or no command -> baseline
        report = orch.run_baseline()
        output_text = json.dumps(report.model_dump(mode="json"), indent=2)
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_text, encoding="utf-8")
            print(f"Report written to {out_path}")
        else:
            print(output_text)
