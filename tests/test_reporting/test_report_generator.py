"""Tests for aegis/reporting/report_generator.py."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from aegis.models import (
    AgentResponse,
    AttackPayload,
    AttackResult,
    EvaluationResult,
    ScoringMethod,
    SecurityReport,
    Severity,
)
from aegis.reporting.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_eval_result(
    owasp_id: str = "LLM01",
    success: bool = True,
    defense_active: str | None = None,
    atlas_technique: str | None = "AML.T0051",
) -> EvaluationResult:
    payload = AttackPayload(
        id=f"{owasp_id}-RG-001",
        attack_module="test_module",
        owasp_id=owasp_id,
        atlas_technique=atlas_technique,
        category="Test Category",
        messages=[{"role": "user", "content": "test"}],
        expected_behavior="test",
        severity=Severity.HIGH,
    )
    response = AgentResponse(
        payload_id=f"{owasp_id}-RG-001",
        agent_profile="default",
        messages=[],
        final_output="agent output",
        tool_calls=[],
        defense_active=defense_active,
    )
    attack_result = AttackResult(
        payload=payload,
        response=response,
        timestamp=datetime.now(UTC),
        run_id="rg-test-run",
    )
    return EvaluationResult(
        attack_result=attack_result,
        success=success,
        confidence=0.8 if success else 0.0,
        scoring_method=ScoringMethod.RULE_BASED,
        explanation="test explanation",
        indicators=["indicator"] if success else [],
        defense_bypassed=None,
        owasp_id=owasp_id,
        atlas_technique=atlas_technique,
    )


# ---------------------------------------------------------------------------
# ReportGenerator.generate()
# ---------------------------------------------------------------------------


class TestReportGeneratorGenerate:
    def test_returns_security_report(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=True)]
        report = rg.generate(results)
        assert isinstance(report, SecurityReport)

    def test_empty_results_returns_zero_stats(self):
        rg = ReportGenerator()
        report = rg.generate([])
        assert report.total_attacks == 0
        assert report.total_successful == 0
        assert report.attack_success_rate == 0.0

    def test_total_attacks_matches_input(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=True) for _ in range(5)]
        report = rg.generate(results)
        assert report.total_attacks == 5

    def test_total_successful_correct(self):
        rg = ReportGenerator()
        results = [
            _make_eval_result(success=True),
            _make_eval_result(success=True),
            _make_eval_result(success=False),
        ]
        report = rg.generate(results)
        assert report.total_successful == 2

    def test_asr_correct(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=True), _make_eval_result(success=False)]
        report = rg.generate(results)
        assert report.attack_success_rate == pytest.approx(0.5)

    def test_results_by_owasp_populated(self):
        rg = ReportGenerator()
        results = [
            _make_eval_result(owasp_id="LLM01", success=True),
            _make_eval_result(owasp_id="ASI01", success=False),
        ]
        report = rg.generate(results)
        assert "LLM01" in report.results_by_owasp
        assert "ASI01" in report.results_by_owasp

    def test_findings_populated_for_successful_attacks(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=True)]
        report = rg.generate(results)
        assert len(report.findings) == 1

    def test_no_findings_for_failed_attacks(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=False) for _ in range(3)]
        report = rg.generate(results)
        assert len(report.findings) == 0

    def test_recommendations_non_empty(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=True)]
        report = rg.generate(results)
        assert len(report.recommendations) > 0

    def test_defense_comparison_set_when_defense_name_provided(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=False)]
        report = rg.generate(results, defense_name="input_validator")
        assert report.defense_comparison is not None
        assert report.defense_comparison["defense_name"] == "input_validator"

    def test_defense_comparison_none_for_baseline(self):
        rg = ReportGenerator()
        results = [_make_eval_result(success=True)]
        report = rg.generate(results, defense_name=None)
        assert report.defense_comparison is None

    def test_owasp_category_name_from_mapper(self):
        """Category names should come from owasp_mapper, not just the payload."""
        rg = ReportGenerator()
        results = [_make_eval_result(owasp_id="LLM01", success=True)]
        report = rg.generate(results)
        assert report.results_by_owasp["LLM01"].category_name == "Prompt Injection"

    def test_testbed_config_stored(self):
        rg = ReportGenerator()
        cfg = {"model": "qwen3:4b"}
        results = [_make_eval_result(success=False)]
        report = rg.generate(results, testbed_config=cfg)
        assert report.testbed_config["model"] == "qwen3:4b"

    def test_report_id_is_unique(self):
        rg = ReportGenerator()
        r1 = rg.generate([_make_eval_result()])
        r2 = rg.generate([_make_eval_result()])
        assert r1.report_id != r2.report_id


# ---------------------------------------------------------------------------
# ReportGenerator.render_html()
# ---------------------------------------------------------------------------


class TestReportGeneratorRenderHtml:
    def test_returns_string(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result()])
        html = rg.render_html(report)
        assert isinstance(html, str)

    def test_html_contains_doctype(self):
        rg = ReportGenerator()
        html = rg.render_html(rg.generate([_make_eval_result()]))
        assert "<!DOCTYPE html>" in html

    def test_html_contains_report_id(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result()])
        html = rg.render_html(report)
        assert report.report_id in html

    def test_html_contains_owasp_id(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result(owasp_id="LLM01")])
        html = rg.render_html(report)
        assert "LLM01" in html

    def test_html_no_successful_attacks_message(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result(success=False)])
        html = rg.render_html(report)
        assert "No successful attacks" in html


# ---------------------------------------------------------------------------
# ReportGenerator.render_json()
# ---------------------------------------------------------------------------


class TestReportGeneratorRenderJson:
    def test_returns_valid_json(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result()])
        json_str = rg.render_json(report)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_contains_report_id(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result()])
        json_str = rg.render_json(report)
        parsed = json.loads(json_str)
        assert parsed["report_id"] == report.report_id

    def test_json_contains_total_attacks(self):
        rg = ReportGenerator()
        results = [_make_eval_result() for _ in range(3)]
        report = rg.generate(results)
        parsed = json.loads(rg.render_json(report))
        assert parsed["total_attacks"] == 3
