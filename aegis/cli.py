"""CLI entry point — Backend Lead implements on Day 11.

Exposes: aegis scan, aegis attack, aegis defend, aegis report, aegis matrix
"""
import typer

app = typer.Typer(
    name="aegis",
    help="AEGIS — Agentic Exploit & Guardrail Investigation Suite",
)

# TODO: Day 11 — add scan, attack, defend, report, matrix commands


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """AEGIS — Agentic Exploit & Guardrail Investigation Suite."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
