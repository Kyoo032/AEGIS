"""Tests for aegis/orchestrator.py."""
from __future__ import annotations

from aegis.models import SecurityReport
from aegis.orchestrator import AEGISOrchestrator


def test_run_baseline_returns_security_report():
    orchestrator = AEGISOrchestrator()
    report = orchestrator.run_baseline()
    assert isinstance(report, SecurityReport)
    assert report.total_attacks > 0


def test_run_with_defense_sets_defense_comparison():
    orchestrator = AEGISOrchestrator()
    report = orchestrator.run_with_defense("input_validator")
    assert report.defense_comparison is not None
    assert report.defense_comparison["defense_name"] == "input_validator"


def test_run_full_matrix_includes_baseline():
    orchestrator = AEGISOrchestrator()
    reports = orchestrator.run_full_matrix()
    assert "baseline" in reports
    assert isinstance(reports["baseline"], SecurityReport)


def test_run_attack_module_works_for_llm01():
    orchestrator = AEGISOrchestrator()
    report = orchestrator.run_attack_module("llm01_prompt_inject")
    assert report.total_attacks > 0
