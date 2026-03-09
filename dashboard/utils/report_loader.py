"""Load and parse AEGIS JSON reports for the dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from aegis.models import SecurityReport


def list_reports(reports_dir: Path) -> list[dict]:
    """Scan a directory for JSON report files and return metadata.

    Returns a list of dicts with keys: name, path, type, timestamp.
    Type is "matrix" if the JSON contains a "scenarios" key, else "report".
    """
    results: list[dict] = []
    for path in sorted(reports_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        report_type = "matrix" if "scenarios" in data else "report"
        timestamp = data.get("generated_at", "")

        results.append({
            "name": path.name,
            "path": str(path),
            "type": report_type,
            "timestamp": timestamp,
        })
    return results


def load_security_report(path: Path) -> SecurityReport:
    """Parse a JSON file into a validated SecurityReport model."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return SecurityReport.model_validate(data)


def load_matrix_summary(path: Path) -> dict:
    """Load a matrix summary JSON file with a 'scenarios' key."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"Expected a JSON object in {path}, got {type(data).__name__}"
        raise ValueError(msg)
    return data


def get_probe_dataframe(report: SecurityReport) -> pd.DataFrame:
    """Convert a SecurityReport's probe_results to a pandas DataFrame."""
    if not report.probe_results:
        return pd.DataFrame()
    return pd.DataFrame(report.probe_results)
