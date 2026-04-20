"""Schema validation tests for matrix and SecurityReport artifacts."""
from __future__ import annotations

import json
from pathlib import Path

from aegis.reporting.report_generator import ReportGenerator
from scripts.validate_reports import validate_files
from tests.test_reporting.test_report_generator import _make_eval_result, _make_phase5_eval_result


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _valid_matrix_payload() -> dict:
    return {
        "generated_at": "2026-02-24T08:17:15Z",
        "baseline": 0.5,
        "errors": [],
        "scenarios": {
            "baseline": {
                "total_attacks": 1,
                "total_successful": 0,
                "attack_success_rate": 0.0,
                "delta_vs_baseline": -0.5,
                "errors": [],
                "probe_results": [
                    {
                        "probe_id": "LLM01-001",
                        "module": "llm01_prompt_inject",
                        "owasp_id": "LLM01",
                        "owasp_category": "Prompt Injection",
                        "passed": True,
                        "success": False,
                        "score": 0.0,
                        "score_method": "rule_based",
                        "response_snippet": "Blocked by policy.",
                        "attack_family": "llm01_prompt_inject",
                        "technique_tag": "direct_override",
                        "expected_signal": "refusal",
                        "is_negative_control": False,
                        "phase5_summary": "Expected signal: refusal"
                    }
                ],
                "module_breakdown": {
                    "llm01_prompt_inject": {
                        "total_attacks": 1,
                        "total_successful": 0,
                        "attack_success_rate": 0.0,
                        "negative_controls": 0,
                        "negative_control_false_positives": 0,
                        "negative_control_false_positive_rate": 0.0
                    }
                },
                "negative_control_summary": {
                    "total": 0,
                    "false_positives": 0,
                    "false_positive_rate": 0.0
                },
            }
        },
    }


def _valid_report_payload() -> dict:
    report = ReportGenerator().generate([_make_eval_result(success=True)])
    return json.loads(ReportGenerator().render_json(report))


def test_matrix_schema_accepts_valid_payload(tmp_path: Path):
    matrix_file = _write_json(tmp_path / "matrix.json", _valid_matrix_payload())
    exit_code = validate_files("matrix", [str(matrix_file)])
    assert exit_code == 0


def test_matrix_schema_rejects_missing_required_field(tmp_path: Path):
    bad = _valid_matrix_payload()
    bad.pop("scenarios")
    matrix_file = _write_json(tmp_path / "bad-matrix.json", bad)
    exit_code = validate_files("matrix", [str(matrix_file)])
    assert exit_code == 1


def test_report_schema_accepts_valid_payload(tmp_path: Path):
    report_file = _write_json(tmp_path / "report.json", _valid_report_payload())
    exit_code = validate_files("report", [str(report_file)])
    assert exit_code == 0


def test_report_schema_accepts_phase5_payload_fields(tmp_path: Path):
    report = ReportGenerator().generate([
        _make_phase5_eval_result(
            attack_module="llm01_crosslingual",
            owasp_id="LLM01",
            category="Cross-Lingual Prompt Injection",
            metadata={
                "language": "id",
                "technique": "indonesian_injection",
                "expected_signal": "instruction_followed_in_non_english",
                "negative_control": True,
            },
        )
    ])
    payload = json.loads(ReportGenerator().render_json(report))
    report_file = _write_json(tmp_path / "phase5-report.json", payload)
    exit_code = validate_files("report", [str(report_file)])
    assert exit_code == 0


def test_report_schema_rejects_missing_owasp_mapping(tmp_path: Path):
    bad = _valid_report_payload()
    bad["findings"][0].pop("owasp_mapping", None)
    report_file = _write_json(tmp_path / "bad-report.json", bad)
    exit_code = validate_files("report", [str(report_file)])
    assert exit_code == 1
