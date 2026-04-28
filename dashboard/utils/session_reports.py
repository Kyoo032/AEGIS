"""Per-session report directory helpers for dashboard-initiated scans."""
from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st

_SESSION_REPORT_DIR_KEY = "aegis_session_reports_dir"


def get_session_report_dir() -> Path:
    """Return a temp report directory scoped to the current Streamlit session."""
    existing = st.session_state.get(_SESSION_REPORT_DIR_KEY)
    if existing:
        path = Path(str(existing))
        path.mkdir(parents=True, exist_ok=True)
        return path

    path = Path(tempfile.mkdtemp(prefix="aegis-session-"))
    st.session_state[_SESSION_REPORT_DIR_KEY] = str(path)
    return path


def list_session_reports() -> list[dict]:
    """Return dashboard report metadata for the current session directory."""
    existing = st.session_state.get(_SESSION_REPORT_DIR_KEY)
    if not existing:
        return []

    from dashboard.utils.report_loader import list_reports

    return list_reports(Path(str(existing)))
