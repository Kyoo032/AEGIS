"""CLI entry point.

Exposes: aegis scan, aegis attack, aegis defend, aegis report, aegis matrix
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import typer

if TYPE_CHECKING:
    from aegis.models import SecurityReport as _SecurityReport

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
        "Start with `aegis guide` for practical examples.\n\n"
        "Exit codes:\n"
        "  0 = run completed, no successful attacks\n"
        "  1 = runtime/argument/config error\n"
        "  2 = run completed, vulnerabilities found\n"
    ),
)

GUIDE_TEXT = """AEGIS first-time workflow

Recommended path: Docker Compose
  Docker is the default way to run AEGIS because it keeps the scanner in a
  non-root, read-only container with only the reports directory mounted writable.

Before you start:
  docker --version
  docker compose version

Mental model:
  AEGIS sends adversarial prompts and tool-use scenarios to your target agent,
  scores what happened, then writes reports you can inspect.

First Docker run, copy and paste:
  1. Copy operator defaults:
     cp .env.example .env

  2. Choose the Ollama model you want to test by editing .env:
     OLLAMA_MODELS=<your-model>:<tag>
     AEGIS_TARGET_MODEL=<your-model>:<tag>
     # Optional: AEGIS_JUDGE_MODEL=<judge-model>:<tag>

  3. Start the local Ollama service:
     docker compose --profile local up -d ollama

  4. Pull the model from .env into the Ollama container:
     docker compose --profile local run --rm ollama-init

  5. Run a baseline scan:
     docker compose --profile local run --rm aegis scan \\
       --format json \\
       --output /app/reports/first-run

  6. Open the generated JSON report on your host:
     reports/first-run/baseline.json

How to read the result:
  Exit code 0 means the run completed and no successful attacks were found.
  Exit code 2 means the run completed and AEGIS found findings to review.
  Exit code 1 means setup, config, provider, or report rendering failed.

What to do next:
  If you want a human-readable report:
    docker compose run --rm aegis report \\
      --input reports/first-run/baseline.json \\
      --format html \\
      --output reports/first-run/baseline.html

  If one area looks risky, run only that attack module:
    docker compose --profile local run --rm aegis attack \\
      --module llm01_prompt_inject \\
      --output /app/reports/prompt-injection

  If you want to test one guardrail:
    docker compose --profile local run --rm aegis defend \\
      --defense tool_boundary \\
      --output /app/reports/tool-boundary

  If you want a full baseline-vs-defense comparison:
    docker compose --profile local run --rm aegis matrix \\
      --output /app/reports/defense-matrix

Local Python fallback:
  Use this only when you intentionally want to run outside Docker:
    uv sync --dev
    ollama pull <your-model>:<tag>
    export AEGIS_TARGET_MODEL=<your-model>:<tag>
    uv run aegis scan \\
      --output reports/first-run

Command map:
  guide   Shows this first-time workflow.
  scan    Runs the baseline attack suite with no extra defense.
  attack  Runs one attack module for focused debugging.
  defend  Runs all attacks with one named defense enabled.
  matrix  Compares baseline, single defenses, and layered defenses.
  report  Converts an existing JSON report or matrix summary to JSON or HTML.

Important options:
  --config, -c   YAML config path. Overrides AEGIS_CONFIG_PATH.
  --format, -f   Output format: json or html.
  --output, -o   Report/artifact directory, or output file for `report`.
  --module, -m   Attack module name for `attack`.
  --defense, -d  Defense name for `defend`.
  --input, -i    Existing JSON report or matrix summary for `report`.

Need names for modules or defenses?
  Run an invalid name once and AEGIS will print the available choices:
    docker compose run --rm aegis attack --module does_not_exist
    docker compose run --rm aegis defend --defense does_not_exist
"""


def _load_orchestrator() -> type[Any]:
    global AEGISOrchestrator
    if AEGISOrchestrator is None:
        from aegis import orchestrator as orchestrator_module

        AEGISOrchestrator = orchestrator_module.AEGISOrchestrator
    return AEGISOrchestrator


def _load_report_generator() -> type[Any]:
    global ReportGenerator
    if ReportGenerator is None:
        from aegis.reporting import report_generator as report_generator_module

        ReportGenerator = report_generator_module.ReportGenerator
    return ReportGenerator


def _load_security_report_model() -> type[Any]:
    global SecurityReport
    if SecurityReport is None:
        from aegis import models as models_module

        SecurityReport = models_module.SecurityReport
    return SecurityReport


def _load_config() -> Any:
    from aegis.config import load_config

    return load_config


def _resolve_config_path(config: str | None) -> str | None:
    return config or os.environ.get("AEGIS_CONFIG_PATH")


def _resolve_reports_dir(
    output_dir: str | None,
    configured_output_dir: str | None = None,
) -> Path:
    return Path(
        output_dir
        or os.environ.get("AEGIS_REPORTS_DIR")
        or configured_output_dir
        or "./reports"
    )


def _build_orchestrator(config: str | None, output_dir: str | None) -> tuple[Any, Path]:
    orchestrator = _load_orchestrator()(config_path=_resolve_config_path(config))
    configured_output_dir = None
    if isinstance(getattr(orchestrator, "config", None), dict):
        configured_output_dir = str(
            orchestrator.config.get("reporting", {}).get("output_dir") or ""
        )
    reports_dir = _resolve_reports_dir(output_dir, configured_output_dir)
    if isinstance(getattr(orchestrator, "config", None), dict):
        orchestrator.config.setdefault("reporting", {})["output_dir"] = str(reports_dir)
    return orchestrator, reports_dir


def _write_report(report: _SecurityReport, fmt: str, output_dir: Path, stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    generator = _load_report_generator()()
    if fmt == "json":
        out_path = output_dir / f"{stem}.json"
        out_path.write_text(generator.render_json(report), encoding="utf-8")
        return out_path

    out_path = output_dir / f"{stem}.html"
    out_path.write_text(generator.render_html(report), encoding="utf-8")
    return out_path


def _vuln_exit_code(report: _SecurityReport) -> int:
    return EXIT_VULNS_FOUND if report.total_successful > 0 else EXIT_OK


def _matrix_exit_code(reports: dict[str, _SecurityReport]) -> int:
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
def guide() -> None:
    """Show practical CLI workflows, options, and exit-code guidance."""
    typer.echo(GUIDE_TEXT)


@app.command()
def scan(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to the YAML config file. Overrides AEGIS_CONFIG_PATH.",
        ),
    ] = None,
    fmt: Annotated[
        Literal["json", "html"],
        typer.Option("--format", "-f", help="Rendered report format."),
    ] = "json",
    output_dir: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory for scan artifacts and the rendered baseline report.",
        ),
    ] = None,
) -> None:
    """Fast baseline scan for PR/pre-commit checks (single run, no defense matrix)."""
    try:
        orchestrator, reports_dir = _build_orchestrator(config, output_dir)
        report = orchestrator.run_baseline()
        out_path = _write_report(report, fmt, reports_dir, "baseline")
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Baseline report written to {out_path}")
    raise typer.Exit(code=_vuln_exit_code(report))


@app.command()
def attack(
    module: Annotated[
        str,
        typer.Option(
            "--module",
            "-m",
            help="Configured attack module to run, such as llm01_prompt_inject.",
        ),
    ],
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to the YAML config file. Overrides AEGIS_CONFIG_PATH.",
        ),
    ] = None,
    fmt: Annotated[
        Literal["json", "html"],
        typer.Option("--format", "-f", help="Rendered report format."),
    ] = "json",
    output_dir: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory for attack artifacts and the rendered module report.",
        ),
    ] = None,
) -> None:
    """Run a specific attack module."""
    try:
        available_modules = [
            str(name)
            for name in _load_config()(_resolve_config_path(config)).get("attacks", {}).get(
                "modules", []
            )
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
        orchestrator, reports_dir = _build_orchestrator(config, output_dir)
        report = orchestrator.run_attack_module(module)
        out_path = _write_report(
            report,
            fmt,
            reports_dir,
            f"attack-{module}",
        )
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Attack report written to {out_path}")
    raise typer.Exit(code=_vuln_exit_code(report))


@app.command()
def defend(
    defense: Annotated[
        str,
        typer.Option(
            "--defense",
            "-d",
            help="Configured defense to enable, such as input_validator.",
        ),
    ],
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to the YAML config file. Overrides AEGIS_CONFIG_PATH.",
        ),
    ] = None,
    fmt: Annotated[
        Literal["json", "html"],
        typer.Option("--format", "-f", help="Rendered report format."),
    ] = "json",
    output_dir: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory for defense artifacts and the rendered defense report.",
        ),
    ] = None,
) -> None:
    """Run all attacks with one defense enabled."""
    try:
        available_defenses = [
            str(name)
            for name in _load_config()(_resolve_config_path(config)).get("defenses", {}).get(
                "available", []
            )
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
        orchestrator, reports_dir = _build_orchestrator(config, output_dir)
        report = orchestrator.run_with_defense(defense)
        out_path = _write_report(
            report,
            fmt,
            reports_dir,
            f"defense-{defense}",
        )
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Defense report written to {out_path}")
    raise typer.Exit(code=_vuln_exit_code(report))


@app.command()
def matrix(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to the YAML config file. Overrides AEGIS_CONFIG_PATH.",
        ),
    ] = None,
    fmt: Annotated[
        Literal["json", "html"],
        typer.Option("--format", "-f", help="Rendered report format for each scenario."),
    ] = "json",
    output_dir: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory for matrix artifacts, scenario reports, and summary JSON.",
        ),
    ] = None,
) -> None:
    """Comprehensive matrix run for nightly/deep security evaluation."""
    try:
        orchestrator, output_root = _build_orchestrator(config, output_dir)
        reports = orchestrator.run_full_matrix()
        for label, report in reports.items():
            _write_report(report, fmt, output_root, label)
    except Exception as exc:
        _error(str(exc))
        raise typer.Exit(code=EXIT_ERROR) from exc

    typer.echo(f"Matrix reports written to {output_root}")
    raise typer.Exit(code=_matrix_exit_code(reports))


@app.command()
def report(
    input_json: Annotated[
        str,
        typer.Option(
            "--input",
            "-i",
            help="Existing SecurityReport JSON or matrix summary JSON to render.",
        ),
    ],
    fmt: Annotated[
        Literal["json", "html"],
        typer.Option("--format", "-f", help="Rendered report format."),
    ] = "html",
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path, or directory when no filename suffix is provided.",
        ),
    ] = None,
) -> None:
    """Render JSON or HTML output from an existing SecurityReport JSON file."""
    from pydantic import ValidationError

    try:
        payload = json.loads(Path(input_json).read_text(encoding="utf-8"))
        out_path = _resolve_output_path(
            Path(output) if output else _resolve_reports_dir(None),
            stem=Path(input_json).stem,
            fmt=fmt,
        )
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
