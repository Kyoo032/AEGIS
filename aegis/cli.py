"""CLI entry point.

Exposes: aegis scan, aegis attack, aegis defend, aegis report, aegis matrix
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import typer

if TYPE_CHECKING:
    from aegis.models import SecurityReport
    from aegis.orchestrator import AEGISOrchestrator as _AEGISOrchestrator
    from aegis.reporting.report_generator import ReportGenerator as _ReportGenerator

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VULNS_FOUND = 2

AEGISOrchestrator: type[Any] | None = None
ReportGenerator: type[Any] | None = None
SecurityReport: type[Any] | None = None

app = typer.Typer(
    name="aegis",
    help=(
        "AEGIS — Agentic Exploit & Guardrail Investigation Suite\n\n"
        "Exit codes:\n"
        "  0 = run completed, no successful attacks\n"
        "  1 = runtime/argument/config error\n"
        "  2 = run completed, vulnerabilities found\n"
    ),
)


def _load_orchestrator() -> type[Any]:
    global AEGISOrchestrator
    if AEGISOrchestrator is None:
        from aegis.orchestrator import AEGISOrchestrator as orchestrator_cls

        AEGISOrchestrator = orchestrator_cls
    return AEGISOrchestrator


def _load_report_generator() -> type[Any]:
    global ReportGenerator
    if ReportGenerator is None:
        from aegis.reporting.report_generator import ReportGenerator as generator_cls

        ReportGenerator = generator_cls
    return ReportGenerator


def _load_security_report_model() -> type[Any]:
    global SecurityReport
    if SecurityReport is None:
        from aegis.models import SecurityReport as model_cls

        SecurityReport = model_cls
    return SecurityReport


def _load_config() -> Any:
    from aegis.config import load_config

    return load_config


def _write_report(report: "SecurityReport", fmt: str, output_dir: Path, stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    generator = _load_report_generator()()
    if fmt == "json":
        out_path = output_dir / f"{stem}.json"
        out_path.write_text(generator.render_json(report), encoding="utf-8")
        return out_path

    out_path = output_dir / f"{stem}.html"
    out_path.write_text(generator.render_html(report), encoding="utf-8")
    return out_path


def _vuln_exit_code(report: SecurityReport) -> int:
    return EXIT_VULNS_FOUND if report.total_successful > 0 else EXIT_OK


def _matrix_exit_code(reports: dict[str, SecurityReport]) -> int:
    return EXIT_VULNS_FOUND if any(r.total_successful > 0 for r in reports.values()) else EXIT_OK


def _resolve_output_path(output: Path, stem: str, fmt: str) -> Path:
    suffix = f".{fmt}"
    if output.suffix:
        output.parent.mkdir(parents=True, exist_ok=True)
        return output
    output.mkdir(parents=True, exist_ok=True)
    return output / f"{stem}{suffix}"


def _error(message: str) -> None:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)


def _render_matrix_html(matrix_payload: dict[str, object]) -> str:
    scenarios = matrix_payload.get("scenarios", {})
    rows = []
    if isinstance(scenarios, dict):
        for name, data in scenarios.items():
            if not isinstance(data, dict):
                continue
            asr = data.get("attack_success_rate")
            delta = data.get("delta_vs_baseline")
            asr_text = f"{float(asr):.2%}" if isinstance(asr, (int, float)) else "n/a"
            delta_text = f"{float(delta):+.2%}" if isinstance(delta, (int, float)) else "n/a"
            rows.append(
                f"<tr><td>{name}</td><td>{asr_text}</td><td>{delta_text}</td></tr>"
            )
    body = "".join(rows) if rows else "<tr><td colspan='3'>No scenarios found.</td></tr>"
    generated_at = matrix_payload.get("generated_at", "unknown")
    baseline = matrix_payload.get("baseline")
    baseline_text = f"{float(baseline):.2%}" if isinstance(baseline, (int, float)) else "n/a"
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>AEGIS Matrix Report</title></head><body>"
        "<h1>AEGIS Defense Matrix</h1>"
        f"<p>Generated: {generated_at}</p>"
        f"<p>Baseline ASR: {baseline_text}</p>"
        "<table border='1' cellspacing='0' cellpadding='6'>"
        "<tr><th>Scenario</th><th>ASR</th><th>Delta vs Baseline</th></tr>"
        f"{body}</table></body></html>"
    )


@app.command()
def scan(
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[Literal["json", "html"], typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Fast baseline scan for PR/pre-commit checks (single run, no defense matrix)."""
    try:
        orchestrator = _load_orchestrator()(config_path=config)
        report = orchestrator.run_baseline()
        out_path = _write_report(report, fmt, Path(output_dir), "baseline")
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Baseline report written to {out_path}")
    raise typer.Exit(code=_vuln_exit_code(report))


@app.command()
def attack(
    module: Annotated[str, typer.Option("--module", "-m")],
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[Literal["json", "html"], typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Run a specific attack module."""
    try:
        available_modules = [
            str(name) for name in _load_config()(config).get("attacks", {}).get("modules", [])
        ]
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    if module not in available_modules:
        _error(
            f"Unknown attack module '{module}'. "
            f"Available modules: {', '.join(sorted(available_modules))}"
        )
        raise typer.Exit(code=EXIT_ERROR)

    try:
        orchestrator = _load_orchestrator()(config_path=config)
        report = orchestrator.run_attack_module(module)
        out_path = _write_report(report, fmt, Path(output_dir), f"attack-{module}")
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Attack report written to {out_path}")
    raise typer.Exit(code=_vuln_exit_code(report))


@app.command()
def defend(
    defense: Annotated[str, typer.Option("--defense", "-d")],
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[Literal["json", "html"], typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Run all attacks with one defense enabled."""
    try:
        available_defenses = [
            str(name) for name in _load_config()(config).get("defenses", {}).get("available", [])
        ]
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    if defense not in available_defenses:
        _error(
            f"Unknown defense '{defense}'. "
            f"Available defenses: {', '.join(sorted(available_defenses))}"
        )
        raise typer.Exit(code=EXIT_ERROR)

    try:
        orchestrator = _load_orchestrator()(config_path=config)
        report = orchestrator.run_with_defense(defense)
        out_path = _write_report(report, fmt, Path(output_dir), f"defense-{defense}")
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Defense report written to {out_path}")
    raise typer.Exit(code=_vuln_exit_code(report))


@app.command()
def matrix(
    config: Annotated[str | None, typer.Option("--config", "-c")] = None,
    fmt: Annotated[Literal["json", "html"], typer.Option("--format", "-f")] = "json",
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "./reports",
) -> None:
    """Comprehensive matrix run for nightly/deep security evaluation."""
    try:
        orchestrator = _load_orchestrator()(config_path=config)
        reports = orchestrator.run_full_matrix()
        output_root = Path(output_dir)
        for label, report in reports.items():
            _write_report(report, fmt, output_root, label)
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Matrix reports written to {output_root}")
    raise typer.Exit(code=_matrix_exit_code(reports))


@app.command()
def report(
    input_json: Annotated[str, typer.Option("--input", "-i")],
    fmt: Annotated[Literal["json", "html"], typer.Option("--format", "-f")] = "html",
    output: Annotated[str, typer.Option("--output", "-o")] = "./reports/",
) -> None:
    """Render JSON or HTML output from an existing SecurityReport JSON file."""
    from pydantic import ValidationError

    try:
        payload = json.loads(Path(input_json).read_text(encoding="utf-8"))
        out_path = _resolve_output_path(Path(output), stem=Path(input_json).stem, fmt=fmt)
        generator = _load_report_generator()()
        try:
            report_obj = _load_security_report_model().model_validate(payload)
            if fmt == "json":
                out_path.write_text(generator.render_json(report_obj), encoding="utf-8")
            else:
                out_path.write_text(generator.render_html(report_obj), encoding="utf-8")
        except ValidationError:
            # Allow matrix-summary JSON as report input for CI/CD workflows.
            if not isinstance(payload, dict) or "scenarios" not in payload:
                raise
            if fmt == "json":
                out_path.write_text(
                    json.dumps(payload, indent=2, ensure_ascii=True),
                    encoding="utf-8",
                )
            else:
                out_path.write_text(_render_matrix_html(payload), encoding="utf-8")
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"{fmt.upper()} report written to {out_path}")
    raise typer.Exit(code=EXIT_OK)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """AEGIS — Agentic Exploit & Guardrail Investigation Suite."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
