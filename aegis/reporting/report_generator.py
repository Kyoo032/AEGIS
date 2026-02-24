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
        """Build a SecurityReport from evaluation results.

        Args:
            results: Scored evaluation results from a test run.
            defense_name: Active defense name, or None for baseline.
            testbed_config: Agent configuration snapshot (freeform).

        Returns:
            A fully populated SecurityReport.
        """
        grouped: dict[str, list[EvaluationResult]] = defaultdict(list)
        findings: list[Finding] = []
        recommendations: set[str] = set()

        for eval_result in results:
            grouped[eval_result.owasp_id].append(eval_result)
            if not eval_result.success:
                continue

            payload = eval_result.attack_result.payload
            owasp_info = get_owasp_info(payload.owasp_id)
            atlas_info = (
                get_atlas_info(payload.atlas_technique) if payload.atlas_technique else None
            )
            description_parts = [eval_result.explanation, f"OWASP: {owasp_info['name']}"]
            if atlas_info:
                description_parts.append(f"ATLAS: {atlas_info['name']}")

            evidence = eval_result.indicators or [eval_result.attack_result.response.final_output]
            finding = Finding(
                title=f"{payload.owasp_id} attack succeeded ({payload.id})",
                owasp_id=payload.owasp_id,
                owasp_category=owasp_info["name"],
                atlas_technique=payload.atlas_technique,
                mitre_atlas_id=payload.atlas_technique,
                severity=payload.severity,
                description=" | ".join(description_parts),
                evidence=evidence[:5],
                recommendation=_RECOMMENDATIONS_BY_SEVERITY[payload.severity],
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

        probe_results = [
            {
                "probe_id": item.attack_result.payload.id,
                "module": item.attack_result.payload.attack_module,
                "owasp_id": item.attack_result.payload.owasp_id,
                "owasp_category": get_owasp_info(item.attack_result.payload.owasp_id)["name"],
                "passed": not item.success,
                "success": item.success,
                "score": item.confidence,
                "score_method": str(item.scoring_method),
                "response_snippet": _snippet(item.attack_result.response.final_output),
            }
            for item in results
        ]

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
            methodology=_default_methodology(),
            defense_matrix=defense_matrix,
        )

    def render_html(self, report: SecurityReport) -> str:
        """Render a SecurityReport as an HTML string.

        Uses the reporting template at reporting/templates/report.html.j2.
        """
        template = _JINJA_ENV.get_template(_TEMPLATE_NAME)
        categories = sorted(report.results_by_owasp.values(), key=lambda cat: cat.owasp_id)
        findings = sorted(
            report.findings,
            key=lambda finding: (_severity_rank(finding.severity), finding.owasp_id, finding.title),
        )
        severity_counts = _severity_counts(report.findings)
        matrix_rows = _matrix_rows(report)
        methodology = report.methodology or _default_methodology()
        return template.render(
            report=report,
            categories=categories,
            findings=findings,
            severity_counts=severity_counts,
            matrix_rows=matrix_rows,
            methodology=methodology,
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
        "scoring": "Rule-based scoring by default, optional LLM judge scoring.",
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
