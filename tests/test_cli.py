"""Tests for aegis/cli.py."""
from __future__ import annotations

import json
from datetime import UTC, datetime

from typer.testing import CliRunner

from aegis.cli import app
from aegis.models import Finding, OWASPCategoryResult, SecurityReport, Severity


def _sample_report(report_id: str) -> SecurityReport:
    finding = Finding(
        title="Sample finding",
        owasp_id="LLM01",
        severity=Severity.LOW,
        description="Sample description",
        evidence=["sample"],
        recommendation="Sample recommendation",
    )
    category = OWASPCategoryResult(
        owasp_id="LLM01",
        category_name="Prompt Injection",
        total_attacks=1,
        successful_attacks=1,
        attack_success_rate=1.0,
        findings=[finding],
    )
    return SecurityReport(
        report_id=report_id,
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        testbed_config={"agent_profile": "test"},
        total_attacks=1,
        total_successful=1,
        attack_success_rate=1.0,
        results_by_owasp={"LLM01": category},
        findings=[finding],
        recommendations=["Sample recommendation"],
    )


def test_scan_command_writes_json_report(monkeypatch, tmp_path):
    class FakeOrchestrator:
        def __init__(self, config_path=None):
            self.config_path = config_path

        def get_available_attack_modules(self):
            return ["asi01_goal_hijack"]

        def get_available_defenses(self):
            return ["input_validator"]

        def run_baseline(self) -> SecurityReport:
            return _sample_report("baseline")

    monkeypatch.setattr("aegis.cli.AEGISOrchestrator", FakeOrchestrator)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "-f", "json", "-o", str(tmp_path)])
    assert result.exit_code == 2
    report_file = tmp_path / "baseline.json"
    assert report_file.exists()
    payload = json.loads(report_file.read_text(encoding="utf-8"))
    assert payload["report_id"] == "baseline"


def test_report_command_renders_html(tmp_path):
    json_path = tmp_path / "in.json"
    html_path = tmp_path / "out.html"
    json_path.write_text(
        json.dumps(_sample_report("for-html").model_dump(mode="json")),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["report", "-i", str(json_path), "-f", "html", "-o", str(html_path)])
    assert result.exit_code == 0
    assert html_path.exists()
    assert "AEGIS Security Report" in html_path.read_text(encoding="utf-8")


def test_report_command_renders_json(tmp_path):
    json_path = tmp_path / "in.json"
    out_path = tmp_path / "out.json"
    json_path.write_text(
        json.dumps(_sample_report("for-json").model_dump(mode="json")),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["report", "-i", str(json_path), "-f", "json", "-o", str(out_path)])
    assert result.exit_code == 0
    parsed = json.loads(out_path.read_text(encoding="utf-8"))
    assert parsed["report_id"] == "for-json"


def test_attack_unknown_module_lists_available(monkeypatch):
    class FakeOrchestrator:
        def __init__(self, config_path=None):
            self.config_path = config_path

        def get_available_attack_modules(self):
            return ["asi01_goal_hijack", "llm01_prompt_inject"]

    monkeypatch.setattr("aegis.cli.AEGISOrchestrator", FakeOrchestrator)

    runner = CliRunner()
    result = runner.invoke(app, ["attack", "--module", "does_not_exist"])
    assert result.exit_code == 1
    assert "Unknown attack module" in result.output
    assert "asi01_goal_hijack" in result.output


def test_defend_unknown_defense_lists_available(monkeypatch):
    class FakeOrchestrator:
        def __init__(self, config_path=None):
            self.config_path = config_path

        def get_available_defenses(self):
            return ["input_validator", "tool_boundary"]

    monkeypatch.setattr("aegis.cli.AEGISOrchestrator", FakeOrchestrator)

    runner = CliRunner()
    result = runner.invoke(app, ["defend", "--defense", "bad_defense"])
    assert result.exit_code == 1
    assert "Unknown defense" in result.output
    assert "input_validator" in result.output
