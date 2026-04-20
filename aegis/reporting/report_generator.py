"""Standalone ReportGenerator — converts EvaluationResult lists into reports.

Does not depend on AEGISOrchestrator and can be called independently.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aegis.models import (
    EvaluationResult,
    Finding,
    OWASPCategoryResult,
    OWASPMapping,
    SecurityReport,
    Severity,
)
from aegis.reporting.atlas_mapper import get_atlas_info
from aegis.reporting.owasp_mapper import get_owasp_info

_RECOMMENDATIONS_BY_SEVERITY: dict[Severity, str] = {
    Severity.INFORMATIONAL: "Monitor observed behavior and keep regression coverage up to date.",
    Severity.CRITICAL: "Block high-risk tool invocations with strict policy gating.",
    Severity.HIGH: "Strengthen instruction boundary checks and output filtering.",
    Severity.MEDIUM: "Tighten tool parameter validation and monitoring coverage.",
    Severity.LOW: "Track low-risk findings and add regression tests.",
}

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_TEMPLATE_NAME = "report.html.j2"
_JINJA_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "j2")),
)


class ReportGenerator:
    """Converts a list of EvaluationResults into a SecurityReport.

    Enriches findings with OWASP and ATLAS labels from the mappers.
    Can render reports as HTML or JSON.
    """

    def generate(
        self,
        results: list[EvaluationResult],
        defense_name: str | None = None,
        testbed_config: dict[str, Any] | None = None,
        run_errors: list[dict[str, Any]] | None = None,
        defense_matrix: dict[str, Any] | None = None,
        baseline_attack_success_rate: float | None = None,
    ) -> SecurityReport:
        """Build a SecurityReport from evaluation results."""
        grouped: dict[str, list[EvaluationResult]] = defaultdict(list)
        findings: list[Finding] = []
        recommendations: set[str] = set()
        probe_results: list[dict[str, Any]] = []

        for eval_result in results:
            grouped[eval_result.owasp_id].append(eval_result)
            probe_results.append(_probe_result(eval_result))
            if not eval_result.success:
                continue

            payload = eval_result.attack_result.payload
            owasp_info = get_owasp_info(payload.owasp_id)
            atlas_info = (
                get_atlas_info(payload.atlas_technique) if payload.atlas_technique else None
            )
            finding = Finding(
                title=f"{payload.owasp_id} attack succeeded ({payload.id})",
                owasp_id=payload.owasp_id,
                owasp_category=owasp_info["name"],
                atlas_technique=payload.atlas_technique,
                mitre_atlas_id=payload.atlas_technique,
                severity=payload.severity,
                description=_finding_description(eval_result, owasp_info, atlas_info),
                evidence=_finding_evidence(eval_result),
                recommendation=_RECOMMENDATIONS_BY_SEVERITY[payload.severity],
                owasp_mapping=OWASPMapping(
                    owasp_id=payload.owasp_id,
                    owasp_name=owasp_info["name"],
                    mitre_atlas_id=payload.atlas_technique,
                ),
            )
            findings.append(finding)
            recommendations.add(_RECOMMENDATIONS_BY_SEVERITY[payload.severity])

        results_by_owasp: dict[str, OWASPCategoryResult] = {}
        for owasp_id, items in grouped.items():
            total = len(items)
            successful = sum(1 for item in items if item.success)
            asr = successful / total if total else 0.0
            category_name = (
                get_owasp_info(owasp_id).get("name")
                or (items[0].attack_result.payload.category if items else owasp_id)
            )
            category_findings = [f for f in findings if f.owasp_id == owasp_id]
            results_by_owasp[owasp_id] = OWASPCategoryResult(
                owasp_id=owasp_id,
                category_name=category_name,
                total_attacks=total,
                successful_attacks=successful,
                attack_success_rate=asr,
                findings=category_findings,
            )

        total_attacks = len(results)
        total_successful = sum(1 for item in results if item.success)
        asr = (total_successful / total_attacks) if total_attacks else 0.0

        if not recommendations:
            recommendations.add("No successful attacks detected; maintain current controls.")

        delta_vs_baseline: float | None = None
        if baseline_attack_success_rate is not None:
            delta_vs_baseline = asr - baseline_attack_success_rate
            for finding in findings:
                finding.delta_vs_baseline = delta_vs_baseline
            if defense_name and delta_vs_baseline < 0:
                recommendations.add(
                    f"Deploy {defense_name}: observed ASR delta {delta_vs_baseline:.2%} vs baseline."
                )

        defense_comparison: dict[str, Any] | None = None
        if defense_name is not None:
            defense_comparison = {"defense_name": defense_name}
            if baseline_attack_success_rate is not None and delta_vs_baseline is not None:
                defense_comparison.update(
                    {
                        "baseline_attack_success_rate": baseline_attack_success_rate,
                        "defense_attack_success_rate": asr,
                        "delta_attack_success_rate": delta_vs_baseline,
                    }
                )

        methodology = _default_methodology()
        methodology["negative_controls"] = _negative_control_summary(probe_results)

        return SecurityReport(
            report_id=f"report-{uuid4()}",
            generated_at=datetime.now(UTC),
            testbed_config=testbed_config or {},
            total_attacks=total_attacks,
            total_successful=total_successful,
            attack_success_rate=asr,
            results_by_owasp=results_by_owasp,
            defense_comparison=defense_comparison,
            findings=findings,
            recommendations=sorted(recommendations),
            run_errors=list(run_errors or []),
            probe_results=probe_results,
            methodology=methodology,
            defense_matrix=defense_matrix,
        )

    def render_html(self, report: SecurityReport) -> str:
        """Render a SecurityReport as an HTML string."""
        template = _JINJA_ENV.get_template(_TEMPLATE_NAME)
        categories = sorted(report.results_by_owasp.values(), key=lambda cat: cat.owasp_id)
        findings = sorted(
            report.findings,
            key=lambda finding: (_severity_rank(finding.severity), finding.owasp_id, finding.title),
        )
        severity_counts = _severity_counts(report.findings)
        matrix_rows = _matrix_rows(report)
        methodology = report.methodology or _default_methodology()
        phase5_rows = _phase5_rows(report)
        matrix_module_rows = _matrix_module_rows(report)
        return template.render(
            report=report,
            categories=categories,
            findings=findings,
            severity_counts=severity_counts,
            matrix_rows=matrix_rows,
            matrix_module_rows=matrix_module_rows,
            methodology=methodology,
            phase5_rows=phase5_rows,
        )

    def render_json(self, report: SecurityReport) -> str:
        """Render a SecurityReport as a JSON string."""
        payload = report.model_dump(mode="json")
        findings = payload.get("findings", [])
        for finding in findings:
            _enrich_finding_mapping(finding)

        grouped = payload.get("results_by_owasp", {})
        if isinstance(grouped, dict):
            for category_payload in grouped.values():
                if not isinstance(category_payload, dict):
                    continue
                cat_findings = category_payload.get("findings", [])
                if not isinstance(cat_findings, list):
                    continue
                for finding in cat_findings:
                    if isinstance(finding, dict):
                        _enrich_finding_mapping(finding)
        return json.dumps(payload, indent=2, default=str)


def _probe_result(eval_result: EvaluationResult) -> dict[str, Any]:
    attack_result = eval_result.attack_result
    payload = attack_result.payload
    response = attack_result.response
    metadata = payload.metadata if isinstance(payload.metadata, dict) else {}
    retrieval_trace = response.retrieval_trace or []
    included_hits = [
        item for item in retrieval_trace if isinstance(item, dict) and bool(item.get("included"))
    ]
    poisoned_included = [item for item in included_hits if bool(item.get("is_poisoned"))]

    probe = {
        "probe_id": payload.id,
        "module": payload.attack_module,
        "owasp_id": payload.owasp_id,
        "owasp_category": get_owasp_info(payload.owasp_id)["name"],
        "passed": not eval_result.success,
        "success": eval_result.success,
        "score": eval_result.confidence,
        "score_method": str(eval_result.scoring_method),
        "response_snippet": _snippet(response.final_output),
        "attack_family": payload.attack_module,
        "technique_tag": metadata.get("technique"),
        "expected_signal": metadata.get("expected_signal"),
        "is_negative_control": _is_negative_control(metadata),
        "retrieval_trace_count": len(retrieval_trace),
        "retrieval_included_count": len(included_hits),
        "retrieval_poisoned_included_count": len(poisoned_included),
        "phase5_summary": _phase5_summary(eval_result),
    }

    language = metadata.get("language")
    if language:
        probe["payload_language"] = language

    module_name = payload.attack_module
    if module_name == "asi_dynamic_cloak":
        fixture = _dict(metadata.get("fixture_state"))
        probe["cloaking_differential"] = {
            "context_source": metadata.get("context_source"),
            "fixture_url": fixture.get("fixture_url"),
            "scanner_body": _snippet(str(fixture.get("scanner_body", ""))),
            "agent_body": _snippet(str(fixture.get("agent_body", ""))),
        }
    elif module_name == "asi03_identity_privilege":
        probe["identity_chain"] = {
            "campaign_id": metadata.get("campaign_id"),
            "turn_index": metadata.get("turn_index"),
            "delegated_identity": metadata.get("delegated_identity"),
        }
    elif module_name == "asi_semantic_manip":
        probe["manipulation_vector"] = metadata.get("technique")
    elif module_name == "asi07_inter_agent":
        probe["message_provenance"] = metadata.get("peer_message_meta")
    elif module_name == "asi_hitl":
        approval_record = _dict(_dict(metadata.get("fixture_state")).get("approval_record"))
        probe["approval_summary_mismatch"] = {
            "approval_summary": metadata.get("approval_summary"),
            "actual_action": metadata.get("actual_action"),
            "risk_delta": approval_record.get("risk_delta"),
        }
    elif module_name == "asi09_human_trust":
        probe["trust_signal"] = metadata.get("trust_signal")

    return probe


def _finding_description(
    eval_result: EvaluationResult,
    owasp_info: dict[str, Any],
    atlas_info: dict[str, Any] | None,
) -> str:
    payload = eval_result.attack_result.payload
    parts = [eval_result.explanation, f"OWASP: {owasp_info['name']}"]
    if atlas_info:
        parts.append(f"ATLAS: {atlas_info['name']}")
    phase5_summary = _phase5_summary(eval_result)
    if phase5_summary:
        parts.append(f"Phase 5 evidence: {phase5_summary}")
    if payload.expected_behavior:
        parts.append(f"Expected outcome: {payload.expected_behavior}")
    return " | ".join(parts)


def _finding_evidence(eval_result: EvaluationResult) -> list[str]:
    attack_result = eval_result.attack_result
    evidence = list(eval_result.indicators)
    if not evidence:
        evidence.append(_snippet(attack_result.response.final_output))

    phase5_summary = _phase5_summary(eval_result)
    if phase5_summary and phase5_summary not in evidence:
        evidence.append(phase5_summary)

    response = attack_result.response
    if response.tool_calls:
        tool_names = ", ".join(tool.tool_name for tool in response.tool_calls)
        evidence.append(f"Tool calls observed: {tool_names}")

    return evidence[:6]


def _phase5_summary(eval_result: EvaluationResult) -> str:
    payload = eval_result.attack_result.payload
    metadata = payload.metadata if isinstance(payload.metadata, dict) else {}
    module_name = payload.attack_module

    if module_name == "asi_dynamic_cloak":
        fixture = _dict(metadata.get("fixture_state"))
        scanner = _snippet(str(fixture.get("scanner_body", "")), max_len=80)
        agent = _snippet(str(fixture.get("agent_body", "")), max_len=80)
        return f"Cloaking differential: scanner saw '{scanner}' while agent saw '{agent}'."

    if module_name == "asi03_identity_privilege":
        identity = _dict(metadata.get("delegated_identity"))
        sender = identity.get("sender_identity", "unknown")
        verified = identity.get("verified")
        return f"Identity chain: sender={sender}, verified={verified}, technique={metadata.get('technique')}."

    if module_name == "asi_semantic_manip":
        return f"Manipulation vector: {metadata.get('technique', 'unknown')}"

    if module_name == "llm01_crosslingual":
        language = metadata.get("language", "unknown")
        technique = metadata.get("technique", "unknown")
        return f"Language: {language}; technique: {technique}"

    if module_name == "asi07_inter_agent":
        peer_meta = _dict(metadata.get("peer_message_meta"))
        meta = _dict(peer_meta.get("metadata"))
        return (
            "Peer provenance: "
            f"sender={peer_meta.get('sender_identity')}, "
            f"session={peer_meta.get('session_id')}, "
            f"trusted={meta.get('trusted')}, signed={meta.get('signed')}"
        )

    if module_name == "asi_hitl":
        return (
            "Approval summary vs actual action: "
            f"{metadata.get('approval_summary')} -> {metadata.get('actual_action')}"
        )

    if module_name == "asi09_human_trust":
        return (
            "Trust-deception evidence: "
            f"trust_signal={metadata.get('trust_signal')}, "
            f"expected_signal={metadata.get('expected_signal')}"
        )

    if metadata.get("expected_signal"):
        return f"Expected signal: {metadata.get('expected_signal')}"

    return ""


def _phase5_rows(report: SecurityReport) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for probe in report.probe_results:
        if not isinstance(probe, dict):
            continue
        summary = str(probe.get("phase5_summary", "")).strip()
        if not summary or not probe.get("success"):
            continue
        rows.append(
            {
                "probe_id": probe.get("probe_id"),
                "module": probe.get("module"),
                "technique": probe.get("technique_tag"),
                "language": probe.get("payload_language"),
                "summary": summary,
            }
        )
    return rows


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _is_negative_control(metadata: dict[str, Any]) -> bool:
    if isinstance(metadata.get("negative_control"), bool):
        return bool(metadata["negative_control"])
    nested = metadata.get("rule_context")
    if isinstance(nested, dict) and isinstance(nested.get("negative_control"), bool):
        return bool(nested["negative_control"])
    return False


def _negative_control_summary(probe_results: list[dict[str, Any]]) -> dict[str, Any]:
    total = 0
    false_positives = 0
    by_module: dict[str, dict[str, Any]] = {}

    for probe in probe_results:
        if not bool(probe.get("is_negative_control")):
            continue
        total += 1
        module = str(probe.get("module") or "unknown")
        item = by_module.setdefault(
            module,
            {"total": 0, "false_positives": 0, "false_positive_rate": 0.0},
        )
        item["total"] += 1
        if bool(probe.get("success")):
            false_positives += 1
            item["false_positives"] += 1

    for item in by_module.values():
        item["false_positive_rate"] = (
            item["false_positives"] / item["total"] if item["total"] else 0.0
        )

    return {
        "total": total,
        "false_positives": false_positives,
        "false_positive_rate": false_positives / total if total else 0.0,
        "by_module": by_module,
    }


def _matrix_module_rows(report: SecurityReport) -> list[dict[str, Any]]:
    matrix = report.defense_matrix
    if not isinstance(matrix, dict):
        return []

    rows: list[dict[str, Any]] = []
    scenarios = matrix.get("scenarios")
    if not isinstance(scenarios, dict):
        return rows

    for scenario, data in scenarios.items():
        if not isinstance(data, dict):
            continue
        module_breakdown = data.get("module_breakdown")
        if not isinstance(module_breakdown, dict):
            continue
        for module, stats in module_breakdown.items():
            if not isinstance(stats, dict):
                continue
            rows.append(
                {
                    "scenario": scenario,
                    "module": module,
                    "total_attacks": stats.get("total_attacks"),
                    "total_successful": stats.get("total_successful"),
                    "attack_success_rate": stats.get("attack_success_rate"),
                    "negative_control_false_positive_rate": stats.get(
                        "negative_control_false_positive_rate"
                    ),
                }
            )

    return rows


def _severity_rank(severity: Severity) -> int:
    ranking = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }
    return ranking.get(severity, 99)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {sev.value: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def _matrix_rows(report: SecurityReport) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    matrix = report.defense_matrix
    if isinstance(matrix, dict):
        scenarios = matrix.get("scenarios")
        if isinstance(scenarios, dict):
            for scenario, data in scenarios.items():
                if not isinstance(data, dict):
                    continue
                rows.append(
                    {
                        "scenario": scenario,
                        "attack_success_rate": data.get("attack_success_rate"),
                        "delta_vs_baseline": data.get("delta_vs_baseline"),
                    }
                )

    comparison = report.defense_comparison or {}
    if not rows and comparison:
        rows.append(
            {
                "scenario": comparison.get("defense_name", "scenario"),
                "attack_success_rate": comparison.get("defense_attack_success_rate"),
                "delta_vs_baseline": comparison.get("delta_attack_success_rate"),
            }
        )

    return rows


def _snippet(text: str, max_len: int = 220) -> str:
    normalized = " ".join(str(text).split())
    if len(normalized) <= max_len:
        return normalized
    return normalized[: max_len - 3] + "..."


def _default_methodology() -> dict[str, Any]:
    return {
        "frameworks": [
            "OWASP Top 10 for LLM Applications (2025)",
            "OWASP Top 10 for Agentic Applications (2026)",
            "MITRE ATLAS",
            "NIST AI RMF",
        ],
        "scoring": (
            "Rule-based scoring by default, with optional module-aware LLM judge "
            "prompts loaded from per-module rubrics."
        ),
        "pass_fail": "Attack success indicates failed defense posture for that probe.",
    }


def _enrich_finding_mapping(finding: dict[str, Any]) -> None:
    owasp_name = finding.get("owasp_category") or get_owasp_info(
        finding.get("owasp_id", "")
    )["name"]
    finding["owasp_mapping"] = {
        "owasp_id": finding.get("owasp_id"),
        "owasp_name": owasp_name,
        "mitre_atlas_id": finding.get("mitre_atlas_id"),
    }
