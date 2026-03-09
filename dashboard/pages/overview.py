"""Executive summary page for the AEGIS dashboard."""

from __future__ import annotations

import streamlit as st

from dashboard.utils.charts import owasp_bar_chart, severity_donut, trend_line


def render_overview(report_data: dict, all_reports: list[dict]) -> None:
    """Render the executive summary with metrics, charts, and recommendations."""
    st.header("Executive Summary")

    # Metric cards
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Attacks", report_data["total_attacks"])
    col2.metric("Attack Success Rate", f"{report_data['attack_success_rate']:.1%}")
    col3.metric("Findings", len(report_data.get("findings", [])))

    severities = [f["severity"] for f in report_data.get("findings", [])]
    top_severity = _top_severity(severities)
    col4.metric("Top Severity", top_severity)

    # Charts
    left, right = st.columns(2)

    findings_dicts = [
        {"severity": f["severity"], "title": f["title"]}
        for f in report_data.get("findings", [])
    ]
    with left:
        st.plotly_chart(severity_donut(findings_dicts), use_container_width=True)

    with right:
        st.plotly_chart(
            owasp_bar_chart(report_data.get("results_by_owasp", {})),
            use_container_width=True,
        )

    # ASR trend (if multiple reports available)
    report_entries = [
        r for r in all_reports
        if r["type"] == "report" and "attack_success_rate" in r
    ]
    if len(report_entries) > 1:
        st.subheader("ASR Trend")
        st.plotly_chart(trend_line(report_entries), use_container_width=True)

    # Recommendations
    recommendations = report_data.get("recommendations", [])
    if recommendations:
        st.subheader("Recommendations")
        for rec in recommendations:
            st.markdown(f"- {rec}")

    # Testbed config summary
    config = report_data.get("testbed_config", {})
    if config:
        with st.expander("Testbed Configuration"):
            st.json(config)


def _top_severity(severities: list[str]) -> str:
    """Return the highest severity from a list."""
    order = ["critical", "high", "medium", "low", "informational"]
    for level in order:
        if level in severities:
            return level.capitalize()
    return "None"
