"""Tests for aegis/cli.py."""
from __future__ import annotations

import importlib
import json
import sys
from datetime import UTC, datetime

from typer.testing import CliRunner

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


def _reload_cli_module():
    sys.modules.pop("aegis.cli", None)
    return importlib.import_module("aegis.cli")


def test_scan_command_writes_json_report(monkeypatch, tmp_path):
    cli = _reload_cli_module()

    class FakeOrchestrator:
        def __init__(self, config_path=None):
            self.config_path = config_path

        def get_available_attack_modules(self):
            return ["asi01_goal_hijack"]

        def get_available_defenses(self):
            return ["input_validator"]

        def run_baseline(self) -> SecurityReport:
            return _sample_report("baseline")

    monkeypatch.setattr(cli, "AEGISOrchestrator", FakeOrchestrator)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["scan", "-f", "json", "-o", str(tmp_path)])
    assert result.exit_code == 2
    report_file = tmp_path / "baseline.json"
    assert report_file.exists()
    payload = json.loads(report_file.read_text(encoding="utf-8"))
    assert payload["report_id"] == "baseline"


def test_scan_output_dir_controls_orchestrator_artifacts(monkeypatch, tmp_path):
    cli = _reload_cli_module()
    observed = {}

    class FakeOrchestrator:
        def __init__(self, config_path=None):
            self.config_path = config_path
            self.config = {"reporting": {"output_dir": "configured-reports"}}

        def run_baseline(self) -> SecurityReport:
            observed["output_dir"] = self.config["reporting"]["output_dir"]
            return _sample_report("baseline")

    monkeypatch.setattr(cli, "AEGISOrchestrator", FakeOrchestrator)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["scan", "-o", str(tmp_path)])

    assert result.exit_code == 2
    assert observed["output_dir"] == str(tmp_path)
    assert (tmp_path / "baseline.json").exists()


def test_report_command_renders_html(tmp_path):
    cli = _reload_cli_module()
    json_path = tmp_path / "in.json"
    html_path = tmp_path / "out.html"
    json_path.write_text(
        json.dumps(_sample_report("for-html").model_dump(mode="json")),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "-i", str(json_path), "-f", "html", "-o", str(html_path)],
    )
    assert result.exit_code == 0
    assert html_path.exists()
    assert "AEGIS Security Report" in html_path.read_text(encoding="utf-8")


def test_report_command_renders_json(tmp_path):
    cli = _reload_cli_module()
    json_path = tmp_path / "in.json"
    out_path = tmp_path / "out.json"
    json_path.write_text(
        json.dumps(_sample_report("for-json").model_dump(mode="json")),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "-i", str(json_path), "-f", "json", "-o", str(out_path)],
    )
    assert result.exit_code == 0
    parsed = json.loads(out_path.read_text(encoding="utf-8"))
    assert parsed["report_id"] == "for-json"


def test_guide_command_shows_practical_workflows():
    cli = _reload_cli_module()

    runner = CliRunner()
    result = runner.invoke(cli.app, ["guide"])

    assert result.exit_code == 0
    assert "AEGIS first-time workflow" in result.output
    assert "Recommended path: Docker Compose" in result.output
    assert "Mental model" in result.output
    assert "First Docker run, copy and paste" in result.output
    assert "docker compose --profile local run --rm aegis scan" in result.output
    assert "What to do next" in result.output


def test_scan_help_explains_options():
    cli = _reload_cli_module()

    runner = CliRunner()
    result = runner.invoke(cli.app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "Path to the YAML config file" in result.output
    assert "Directory for scan artifacts" in result.output


def test_attack_unknown_module_lists_available(monkeypatch):
    cli = _reload_cli_module()

    runner = CliRunner()
    result = runner.invoke(cli.app, ["attack", "--module", "does_not_exist"])
    assert result.exit_code == 1
    assert "Unknown attack module" in result.output
    assert "asi01_goal_hijack" in result.output


def test_defend_unknown_defense_lists_available(monkeypatch):
    cli = _reload_cli_module()

    runner = CliRunner()
    result = runner.invoke(cli.app, ["defend", "--defense", "bad_defense"])
    assert result.exit_code == 1
    assert "Unknown defense" in result.output
    assert "input_validator" in result.output


def test_cli_import_is_lazy():
    for module_name in list(sys.modules):
        if module_name == "aegis.cli" or module_name.startswith("aegis.orchestrator"):
            sys.modules.pop(module_name, None)
        if module_name.startswith("aegis.reporting.report_generator"):
            sys.modules.pop(module_name, None)

    _reload_cli_module()

    assert "aegis.orchestrator" not in sys.modules
    assert "aegis.reporting.report_generator" not in sys.modules


def test_invalid_attack_does_not_import_orchestrator():
    cli = _reload_cli_module()
    sys.modules.pop("aegis.orchestrator", None)

    runner = CliRunner()
    result = runner.invoke(cli.app, ["attack", "--module", "does_not_exist"])

    assert result.exit_code == 1
    assert "aegis.orchestrator" not in sys.modules
