"""Standalone ReportGenerator — converts EvaluationResult lists into reports.

Does not depend on AEGISOrchestrator and can be called independently.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

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
    Severity.CRITICAL: "Block high-risk tool invocations with strict policy gating.",
    Severity.HIGH: "Strengthen instruction boundary checks and output filtering.",
    Severity.MEDIUM: "Tighten tool parameter validation and monitoring coverage.",
    Severity.LOW: "Track low-risk findings and add regression tests.",
}

# Inline Jinja2-style HTML template — no external file dependency.
_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>AEGIS Security Report {report_id}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; color: #333; }}
    h1 {{ color: #c0392b; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
    th, td {{ border: 1px solid #ddd; padding: .5rem; text-align: left; }}
    th {{ background: #f4f4f4; }}
    .critical {{ color: #c0392b; font-weight: bold; }}
    .high {{ color: #e67e22; }}
    .medium {{ color: #f1c40f; }}
    .low {{ color: #27ae60; }}
  </style>
</head>
<body>
  <h1>AEGIS Security Report</h1>
  <p><strong>Report ID:</strong> {report_id}</p>
  <p><strong>Generated:</strong> {generated_at}</p>
  <p><strong>Total Attacks:</strong> {total_attacks} | <strong>Successful:</strong> {total_successful} | <strong>ASR:</strong> {asr:.1%}</p>
  <h2>Results by OWASP Category</h2>
  <table>
    <tr><th>OWASP ID</th><th>Category</th><th>Total</th><th>Successful</th><th>ASR</th></tr>
    {owasp_rows}
  </table>
  <h2>Findings</h2>
  {findings_html}
  <h2>Recommendations</h2>
  <ul>
    {recommendations_html}
  </ul>
</body>
</html>
"""


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
                atlas_technique=payload.atlas_technique,
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

        defense_comparison: dict[str, Any] | None = None
        if defense_name is not None:
            defense_comparison = {"defense_name": defense_name}

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
        )

    def render_html(self, report: SecurityReport) -> str:
        """Render a SecurityReport as an HTML string.

        Uses an inline template — no external file required.
        """
        owasp_rows = "\n    ".join(
            f"<tr>"
            f"<td>{cat.owasp_id}</td>"
            f"<td>{cat.category_name}</td>"
            f"<td>{cat.total_attacks}</td>"
            f"<td>{cat.successful_attacks}</td>"
            f"<td>{cat.attack_success_rate:.1%}</td>"
            f"</tr>"
            for cat in report.results_by_owasp.values()
        )

        if report.findings:
            findings_html = "<ul>" + "".join(
                f"<li class='{f.severity}'><strong>{f.title}</strong>: {f.description}</li>"
                for f in report.findings
            ) + "</ul>"
        else:
            findings_html = "<p>No successful attacks detected.</p>"

        recommendations_html = "\n    ".join(
            f"<li>{rec}</li>" for rec in report.recommendations
        )

        return _HTML_TEMPLATE.format(
            report_id=report.report_id,
            generated_at=report.generated_at.isoformat(),
            total_attacks=report.total_attacks,
            total_successful=report.total_successful,
            asr=report.attack_success_rate,
            owasp_rows=owasp_rows,
            findings_html=findings_html,
            recommendations_html=recommendations_html,
        )

    def render_json(self, report: SecurityReport) -> str:
        """Render a SecurityReport as a JSON string."""
        return json.dumps(report.model_dump(mode="json"), indent=2, default=str)
