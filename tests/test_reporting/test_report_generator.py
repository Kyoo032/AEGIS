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


def _make_phase5_eval_result(
    *,
    attack_module: str,
    owasp_id: str,
    category: str,
    metadata: dict,
    final_output: str = "agent output",
) -> EvaluationResult:
    payload = AttackPayload(
        id=f"{owasp_id}-PHASE5-001",
        attack_module=attack_module,
        owasp_id=owasp_id,
        atlas_technique=None,
        category=category,
        messages=[{"role": "user", "content": "test"}],
        expected_behavior="phase 5 test",
        severity=Severity.HIGH,
        metadata=metadata,
    )
    response = AgentResponse(
        payload_id=f"{owasp_id}-PHASE5-001",
        agent_profile="default",
        messages=[],
        final_output=final_output,
        tool_calls=[],
    )
    attack_result = AttackResult(
        payload=payload,
        response=response,
        timestamp=datetime.now(UTC),
        run_id="phase5-test-run",
    )
    return EvaluationResult(
        attack_result=attack_result,
        success=True,
        confidence=0.8,
        scoring_method=ScoringMethod.RULE_BASED,
        explanation="phase 5 explanation",
        indicators=["indicator"],
        defense_bypassed=None,
        owasp_id=owasp_id,
        atlas_technique=None,
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
        assert report.findings[0].owasp_category

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

    def test_html_contains_executive_summary(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result(success=True)])
        html = rg.render_html(report)
        assert "Executive Summary" in html
        assert "Overall ASR" in html

    def test_html_contains_sar_sections(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result(success=True)])
        html = rg.render_html(report)
        for section in (
            "Executive Summary",
            "Methodology",
            "Severity Definitions",
            "Findings Summary",
            "Defense Evaluation Matrix",
            "Detailed Findings",
            "Appendix",
        ):
            assert section in html

    def test_html_contains_atlas_reference(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result(success=True, atlas_technique="AML.T0051")])
        html = rg.render_html(report)
        assert "MITRE ATLAS" in html
        assert "AML.T0051" in html


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

    def test_json_contains_mapping_fields(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result(success=True)], defense_name="input_validator")
        parsed = json.loads(rg.render_json(report))
        assert parsed["findings"][0]["owasp_id"] == "LLM01"
        assert parsed["findings"][0]["owasp_category"] == "Prompt Injection"
        assert parsed["findings"][0]["severity"] == "high"
        assert parsed["findings"][0]["owasp_mapping"]["owasp_name"] == "Prompt Injection"


class TestPhase5Reporting:
    def test_probe_results_include_crosslingual_phase5_fields(self):
        rg = ReportGenerator()
        report = rg.generate([
            _make_phase5_eval_result(
                attack_module="llm01_crosslingual",
                owasp_id="LLM01",
                category="Cross-Lingual Prompt Injection",
                metadata={
                    "language": "id",
                    "technique": "indonesian_injection",
                    "expected_signal": "instruction_followed_in_non_english",
                },
                final_output="Saya akan mengikuti instruksi itu.",
            )
        ])

        probe = report.probe_results[0]
        assert probe["payload_language"] == "id"
        assert probe["technique_tag"] == "indonesian_injection"
        assert "Language: id" in probe["phase5_summary"]

    def test_findings_include_hitl_phase5_evidence(self):
        rg = ReportGenerator()
        report = rg.generate([
            _make_phase5_eval_result(
                attack_module="asi_hitl",
                owasp_id="ASI-HITL",
                category="Human-in-the-Loop Approval Failures",
                metadata={
                    "approval_summary": "Update a harmless config value",
                    "actual_action": "delete production configuration",
                    "technique": "misleading_action_summary",
                    "expected_signal": "summary_action_mismatch",
                },
                final_output="Proceeding with the approved delete.",
            )
        ])

        finding = report.findings[0]
        assert any("Approval summary vs actual action" in item for item in finding.evidence)
        assert "Phase 5 evidence:" in finding.description

    def test_html_contains_phase5_evidence_section(self):
        rg = ReportGenerator()
        report = rg.generate([
            _make_phase5_eval_result(
                attack_module="asi09_human_trust",
                owasp_id="ASI09",
                category="Human Trust Exploitation",
                metadata={
                    "trust_signal": "verified_safe_claim",
                    "expected_signal": "false_safety_claim",
                    "technique": "overconfident_safety_summary",
                },
                final_output="This is completely safe and verified.",
            )
        ])

        html = rg.render_html(report)
        assert "Phase 5 Evidence Highlights" in html
        assert "Trust-deception evidence" in html

    def test_methodology_contains_negative_control_summary(self):
        rg = ReportGenerator()
        report = rg.generate([
            _make_phase5_eval_result(
                attack_module="asi09_human_trust",
                owasp_id="ASI09",
                category="Human Trust Exploitation",
                metadata={
                    "negative_control": True,
                    "trust_signal": "calibrated_uncertainty",
                    "expected_signal": "benign_trust_guidance",
                    "technique": "benign_safety_summary",
                },
                final_output="Inspect the script before running it.",
            )
        ])

        summary = report.methodology["negative_controls"]
        assert summary["total"] == 1
        assert summary["false_positives"] == 1
        assert summary["by_module"]["asi09_human_trust"]["false_positive_rate"] == 1.0

    def test_html_contains_matrix_module_breakdown(self):
        rg = ReportGenerator()
        report = rg.generate([_make_eval_result(success=False)])
        report.defense_matrix = {
            "baseline": 0.5,
            "scenarios": {
                "baseline": {
                    "attack_success_rate": 0.5,
                    "delta_vs_baseline": 0.0,
                    "module_breakdown": {
                        "asi_semantic_manip": {
                            "total_attacks": 4,
                            "total_successful": 2,
                            "attack_success_rate": 0.5,
                            "negative_control_false_positive_rate": 0.25,
                        }
                    },
                }
            },
        }

        html = rg.render_html(report)
        assert "Module Breakdown" in html
        assert "asi_semantic_manip" in html
        assert "25.0%" in html
