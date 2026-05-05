"""AEGIS orchestration pipeline."""
from __future__ import annotations

import json
import logging
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any
from uuid import uuid4

from aegis.attacks.base import BaseAttackModule
from aegis.config import load_config
from aegis.evidence.store import EvidenceTraceStore
from aegis.interfaces.attack import AttackModule
from aegis.interfaces.scorer import Scorer
from aegis.interfaces.scorer_protocol import ScorerProtocol
from aegis.lazy_loading import load_symbol
from aegis.models import AttackResult, EvaluationResult, SecurityReport, TraceRecord

logger = logging.getLogger(__name__)


def _load_default_agent():
    return load_symbol("aegis.testbed.agent", "DefaultAgent")


def _load_evaluation_pipeline():
    return load_symbol("aegis.evaluation.pipeline", "EvaluationPipeline")


def _load_protocol_scorer_adapter():
    return load_symbol("aegis.evaluation.protocol_adapter", "ProtocolScorerAdapter")


def _load_prompt_injection_module():
    return load_symbol("aegis.attacks.llm01_prompt_inject", "PromptInjectionModule")


def _load_report_generator():
    return load_symbol("aegis.reporting.report_generator", "ReportGenerator")


def _load_rule_based_scorer():
    return load_symbol("aegis.evaluation.scorer", "RuleBasedScorer")


class AEGISOrchestrator:
    """Run attacks against the testbed agent and produce security reports."""

    def __init__(
        self,
        config_path: str | None = None,
        scorers: list[Scorer] | None = None,
        protocol_scorers: list[ScorerProtocol] | None = None,
    ) -> None:
        self.config = load_config(config_path)
        self._agent: Any | None = None
        self.attacks: list[AttackModule] | None = None

        configured_scorers: list[Scorer] = (
            list(scorers) if scorers is not None else self._load_scorers()
        )
        if protocol_scorers:
            adapter_cls = _load_protocol_scorer_adapter()
            configured_scorers.extend(adapter_cls(scorer) for scorer in protocol_scorers)
        if not configured_scorers:
            configured_scorers = [_load_rule_based_scorer()()]
        self.scorers = configured_scorers

        self._last_run_errors: list[dict[str, Any]] = []

    @property
    def agent(self) -> Any:
        if self._agent is None:
            self._agent = _load_default_agent()(config=dict(self.config["testbed"]))
        return self._agent

    @agent.setter
    def agent(self, value: Any) -> None:
        self._agent = value

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

        matrix_path, matrix_payload = self._write_matrix_summary(reports)
        for scenario, report in reports.items():
            report.defense_matrix = {
                **matrix_payload,
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
            attacks = self._get_attacks()
        self._preflight_agent_provider()
        payload_limit = self._payloads_per_module_limit()

        run_id = str(uuid4())
        output_dir = Path(self.config["reporting"].get("output_dir", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        results_path = output_dir / f"attack_results_{run_id}.jsonl"
        trace_store = EvidenceTraceStore(output_dir)
        trace_store.output_dir.mkdir(parents=True, exist_ok=True)
        trace_path = trace_store.path_for_run(run_id)

        errors: list[dict[str, Any]] = []
        count = 0
        with (
            results_path.open("w", encoding="utf-8") as results_fh,
            trace_path.open("a", encoding="utf-8") as trace_fh,
        ):
            for attack in attacks:
                module_name = getattr(attack, "name", attack.__class__.__name__)
                try:
                    attack.generate_payloads(self.agent.get_config())
                    if payload_limit > 0:
                        attack.limit_payloads(payload_limit)
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
                    results_fh.write(result.model_dump_json() + "\n")
                    trace_fh.write(_trace_record_from_attack_result(result).model_dump_json() + "\n")
                    count += 1

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

    def _preflight_agent_provider(self) -> None:
        """Initialize the agent once so provider/key failures happen before attack execution."""
        self.agent.get_config()

    def _payloads_per_module_limit(self) -> int:
        value = self.config.get("attacks", {}).get("payloads_per_module", 0)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

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

        pipeline = _load_evaluation_pipeline()(
            scorers=self.scorers,
            config=dict(self.config.get("evaluation", {})),
        )
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
        generator = _load_report_generator()()
        return generator.generate(
            eval_results,
            defense_name=defense_name,
            testbed_config=self.agent.get_config(),
            run_errors=run_errors,
        )

    def get_available_attack_modules(self) -> list[str]:
        """Return configured attack module names."""
        return [str(name) for name in self.config["attacks"]["modules"]]

    def get_available_defenses(self) -> list[str]:
        """Return configured defense names."""
        return [str(name) for name in self.config["defenses"]["available"]]

    def _get_attacks(self) -> list[AttackModule]:
        if self.attacks is None:
            self.attacks = self._load_attacks()
        return self.attacks

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
            attacks.append(_load_prompt_injection_module()())
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
        rule_based_scorer_cls = _load_rule_based_scorer()
        for name in scorer_names:
            if name == "rule_based":
                scorers.append(rule_based_scorer_cls())
            elif name == "llm_judge":
                scorers.append(self._build_llm_judge_scorer())
            else:
                logger.warning("Skipping unavailable scorer '%s'", name)
        if not scorers:
            scorers.append(rule_based_scorer_cls())
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

    def _write_matrix_summary(self, reports: dict[str, SecurityReport]) -> tuple[Path, dict[str, Any]]:
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
                "module_breakdown": _module_breakdown(report.probe_results),
                "negative_control_summary": _negative_control_summary(report.probe_results),
            }

        path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
        logger.info("Wrote defense matrix summary to %s", path)
        return path, matrix


def _module_breakdown(probe_results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    breakdown: dict[str, dict[str, Any]] = {}
    for probe in probe_results:
        module = str(probe.get("module") or "unknown")
        item = breakdown.setdefault(
            module,
            {
                "total_attacks": 0,
                "total_successful": 0,
                "attack_success_rate": 0.0,
                "negative_controls": 0,
                "negative_control_false_positives": 0,
                "negative_control_false_positive_rate": 0.0,
            },
        )
        item["total_attacks"] += 1
        if bool(probe.get("success")):
            item["total_successful"] += 1
        if bool(probe.get("is_negative_control")):
            item["negative_controls"] += 1
            if bool(probe.get("success")):
                item["negative_control_false_positives"] += 1

    for item in breakdown.values():
        item["attack_success_rate"] = (
            item["total_successful"] / item["total_attacks"]
            if item["total_attacks"]
            else 0.0
        )
        item["negative_control_false_positive_rate"] = (
            item["negative_control_false_positives"] / item["negative_controls"]
            if item["negative_controls"]
            else 0.0
        )
    return breakdown


def _negative_control_summary(probe_results: list[dict[str, Any]]) -> dict[str, Any]:
    total = sum(1 for probe in probe_results if bool(probe.get("is_negative_control")))
    false_positives = sum(
        1
        for probe in probe_results
        if bool(probe.get("is_negative_control")) and bool(probe.get("success"))
    )
    return {
        "total": total,
        "false_positives": false_positives,
        "false_positive_rate": false_positives / total if total else 0.0,
    }


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
