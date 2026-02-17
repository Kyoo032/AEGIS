"""CLI entry point.

Exposes: aegis scan, aegis attack, aegis defend, aegis report, aegis matrix
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from aegis.models import SecurityReport
from aegis.orchestrator import AEGISOrchestrator

app = typer.Typer(
    name="aegis",
    help="AEGIS — Agentic Exploit & Guardrail Investigation Suite",
)


def _write_report(report: SecurityReport, fmt: str, output_dir: Path, stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        out_path = output_dir / f"{stem}.json"
        out_path.write_text(
            json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
        return out_path

    out_path = output_dir / f"{stem}.html"
    out_path.write_text(_render_html_report(report), encoding="utf-8")
    return out_path


def _render_html_report(report: SecurityReport) -> str:
    rows = "".join(
        (
            f"<tr><td>{owasp}</td><td>{result.total_attacks}</td>"
            f"<td>{result.successful_attacks}</td><td>{result.attack_success_rate:.2%}</td></tr>"
        )
        for owasp, result in report.results_by_owasp.items()
    )
    findings = "".join(
        f"<li><strong>{finding.title}</strong>: {finding.description}</li>"
        for finding in report.findings
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>AEGIS Security Report</title></head><body>"
        f"<h1>AEGIS Security Report</h1><p>Report ID: {report.report_id}</p>"
        f"<p>Total attacks: {report.total_attacks}; Successes: {report.total_successful}; "
        f"ASR: {report.attack_success_rate:.2%}</p>"
        "<h2>Results by OWASP</h2>"
        "<table border='1' cellspacing='0' cellpadding='6'>"
        "<tr><th>OWASP</th><th>Total</th><th>Successful</th><th>ASR</th></tr>"
        f"{rows}</table><h2>Findings</h2><ul>{findings}</ul></body></html>"
    )


@app.command()
def scan(
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Run all configured attacks with no defenses enabled."""
    orchestrator = AEGISOrchestrator(config_path=config)
    report = orchestrator.run_baseline()
    out_path = _write_report(report, fmt, Path(output_dir), "baseline")
    typer.echo(f"Baseline report written to {out_path}")


@app.command()
def attack(
    module: Annotated[str, typer.Option("--module", "-m")],
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Run a specific attack module."""
    orchestrator = AEGISOrchestrator(config_path=config)
    report = orchestrator.run_attack_module(module)
    out_path = _write_report(report, fmt, Path(output_dir), f"attack-{module}")
    typer.echo(f"Attack report written to {out_path}")


@app.command()
def defend(
    defense: Annotated[str, typer.Option("--defense", "-d")],
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Run all attacks with one defense enabled."""
    orchestrator = AEGISOrchestrator(config_path=config)
    report = orchestrator.run_with_defense(defense)
    out_path = _write_report(report, fmt, Path(output_dir), f"defense-{defense}")
    typer.echo(f"Defense report written to {out_path}")


@app.command()
def matrix(
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Run baseline + every configured defense."""
    orchestrator = AEGISOrchestrator(config_path=config)
    reports = orchestrator.run_full_matrix()
    output_root = Path(output_dir)
    for label, report in reports.items():
        _write_report(report, fmt, output_root, label)
    typer.echo(f"Matrix reports written to {output_root}")


@app.command()
def report(
    input_json: Annotated[str, typer.Option("--input", "-i")],
    output_html: Annotated[str, typer.Option("--output", "-o")] = "./reports/report.html",
) -> None:
    """Render HTML report from an existing JSON report file."""
    payload = json.loads(Path(input_json).read_text(encoding="utf-8"))
    report_obj = SecurityReport.model_validate(payload)
    html = _render_html_report(report_obj)
    out_path = Path(output_html)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    typer.echo(f"HTML report written to {out_path}")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """AEGIS — Agentic Exploit & Guardrail Investigation Suite."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
