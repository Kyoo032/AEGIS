"""Tests for dashboard report loading utilities."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from aegis.models import SecurityReport
from dashboard.utils.report_loader import (
    get_probe_dataframe,
    list_reports,
    load_matrix_summary,
    load_security_report,
)


def _make_minimal_report() -> dict:
    """Return a minimal valid SecurityReport dict."""
    return {
        "report_id": "test-001",
        "generated_at": "2026-01-15T12:00:00Z",
        "testbed_config": {"model": "test"},
        "total_attacks": 10,
        "total_successful": 3,
        "attack_success_rate": 0.3,
        "results_by_owasp": {
            "ASI01": {
                "owasp_id": "ASI01",
                "category_name": "Agent Goal Hijacking",
                "total_attacks": 5,
                "successful_attacks": 2,
                "attack_success_rate": 0.4,
                "findings": [],
            },
        },
        "findings": [
            {
                "title": "Test finding",
                "owasp_id": "ASI01",
                "severity": "high",
                "description": "A test finding",
                "evidence": ["evidence1"],
                "recommendation": "Fix it",
            },
        ],
        "recommendations": ["Harden the agent"],
        "probe_results": [
            {
                "payload_id": "ASI01-001",
                "owasp_id": "ASI01",
                "success": True,
                "severity": "high",
                "category": "Agent Goal Hijacking",
            },
            {
                "payload_id": "ASI01-002",
                "owasp_id": "ASI01",
                "success": False,
                "severity": "medium",
                "category": "Agent Goal Hijacking",
            },
        ],
    }


def _make_matrix_summary() -> dict:
    """Return a minimal matrix summary dict."""
    return {
        "scenarios": [
            {
                "name": "baseline",
                "total_attacks": 86,
                "successful_attacks": 61,
                "attack_success_rate": 0.709,
            },
            {
                "name": "input_validator",
                "total_attacks": 86,
                "successful_attacks": 45,
                "attack_success_rate": 0.523,
            },
        ],
    }


class TestListReports:
    def test_finds_json_files(self, tmp_path: Path) -> None:
        (tmp_path / "report_a.json").write_text(json.dumps(_make_minimal_report()))
        (tmp_path / "report_b.json").write_text(json.dumps(_make_matrix_summary()))
        (tmp_path / "notes.txt").write_text("not a report")

        result = list_reports(tmp_path)
        assert len(result) == 2
        names = {r["name"] for r in result}
        assert "report_a.json" in names
        assert "report_b.json" in names
        assert all("path" in r for r in result)

    def test_empty_dir(self, tmp_path: Path) -> None:
        result = list_reports(tmp_path)
        assert result == []

    def test_classifies_matrix_reports(self, tmp_path: Path) -> None:
        (tmp_path / "matrix.json").write_text(json.dumps(_make_matrix_summary()))
        result = list_reports(tmp_path)
        assert result[0]["type"] == "matrix"

    def test_classifies_security_reports(self, tmp_path: Path) -> None:
        (tmp_path / "report.json").write_text(json.dumps(_make_minimal_report()))
        result = list_reports(tmp_path)
        assert result[0]["type"] == "report"


class TestLoadSecurityReport:
    def test_valid_report(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        path.write_text(json.dumps(_make_minimal_report()))
        report = load_security_report(path)
        assert isinstance(report, SecurityReport)
        assert report.report_id == "test-001"
        assert report.total_attacks == 10
        assert report.attack_success_rate == 0.3

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{invalid json")
        with pytest.raises(Exception):
            load_security_report(path)

    def test_missing_fields(self, tmp_path: Path) -> None:
        path = tmp_path / "incomplete.json"
        path.write_text(json.dumps({"report_id": "only-this"}))
        with pytest.raises(Exception):
            load_security_report(path)


class TestLoadMatrixSummary:
    def test_valid_matrix(self, tmp_path: Path) -> None:
        path = tmp_path / "matrix.json"
        path.write_text(json.dumps(_make_matrix_summary()))
        result = load_matrix_summary(path)
        assert "scenarios" in result
        assert len(result["scenarios"]) == 2

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json at all")
        with pytest.raises(Exception):
            load_matrix_summary(path)


class TestGetProbeDataframe:
    def test_returns_dataframe_with_expected_columns(self) -> None:
        data = _make_minimal_report()
        report = SecurityReport.model_validate(data)
        df = get_probe_dataframe(report)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert "payload_id" in df.columns
        assert "owasp_id" in df.columns
        assert "success" in df.columns

    def test_empty_probe_results(self) -> None:
        data = _make_minimal_report()
        data["probe_results"] = []
        report = SecurityReport.model_validate(data)
        df = get_probe_dataframe(report)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0
