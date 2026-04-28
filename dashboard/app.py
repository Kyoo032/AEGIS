"""AEGIS Security Dashboard — Streamlit entry point."""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from dashboard.utils.report_loader import (
    list_reports,
    load_matrix_summary,
    load_security_report,
)

REPORTS_DIR = Path(os.environ.get("AEGIS_REPORTS_DIR", "./reports"))

st.set_page_config(page_title="AEGIS Dashboard", layout="wide", page_icon="🛡️")


@st.cache_data
def _cached_list_reports(reports_dir: str) -> list[dict]:
    return list_reports(Path(reports_dir))


@st.cache_data
def _cached_load_report(path: str) -> dict:
    report = load_security_report(Path(path))
    return report.model_dump()


@st.cache_data
def _cached_load_matrix(path: str) -> dict:
    return load_matrix_summary(Path(path))


def _safe_list_session_reports() -> list[dict]:
    try:
        from dashboard.utils.session_reports import list_session_reports

        return list_session_reports()
    except Exception:
        return []


def main() -> None:
    st.title("AEGIS Security Dashboard")

    reports = _cached_list_reports(str(REPORTS_DIR)) + _safe_list_session_reports()

    if not reports:
        st.warning(
            f"No JSON reports found in `{REPORTS_DIR}`. "
            "Run an AEGIS scan first: `aegis scan --format json`"
        )
        st.info("Use the Run Scan button to create a dashboard report from this session.")
        if st.sidebar.button("Run Scan") is True:
            from dashboard.pages.run_scan import render_run_scan

            render_run_scan()
        return

    # Sidebar controls
    st.sidebar.header("Report Selection")

    report_type = st.sidebar.radio("Report type", ["report", "matrix"], index=0)
    filtered = [r for r in reports if r["type"] == report_type]

    if not filtered:
        st.sidebar.warning(f"No {report_type} files found.")
        return

    names = [r["name"] for r in filtered]
    selected_name = st.sidebar.selectbox("Select report", names)
    selected = next(r for r in filtered if r["name"] == selected_name)

    # Navigation
    page = st.sidebar.radio(
        "Page",
        ["Overview", "OWASP Breakdown", "Defense Matrix", "Findings", "Run Scan"],
    )

    if page == "Run Scan":
        from dashboard.pages.run_scan import render_run_scan

        render_run_scan()
        return

    # Load and render
    if report_type == "report":
        report_data = _cached_load_report(selected["path"])
        _render_report_page(page, report_data, reports)
    else:
        matrix_data = _cached_load_matrix(selected["path"])
        _render_matrix_page(page, matrix_data)


def _render_report_page(page: str, report_data: dict, all_reports: list[dict]) -> None:
    from dashboard.pages.findings import render_findings
    from dashboard.pages.overview import render_overview
    from dashboard.pages.owasp_breakdown import render_owasp_breakdown

    if page == "Overview":
        render_overview(report_data, all_reports)
    elif page == "OWASP Breakdown":
        render_owasp_breakdown(report_data)
    elif page == "Findings":
        render_findings(report_data)
    elif page == "Defense Matrix":
        st.info("Select a matrix-type report for Defense Matrix view.")


def _render_matrix_page(page: str, matrix_data: dict) -> None:
    from dashboard.pages.defense_matrix import render_defense_matrix

    if page == "Defense Matrix":
        render_defense_matrix(matrix_data)
    else:
        st.info("Select a report-type file for this view, or switch to Defense Matrix page.")


if __name__ == "__main__":
    main()
