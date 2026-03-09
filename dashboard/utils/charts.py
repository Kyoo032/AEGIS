"""Plotly chart helpers for the AEGIS dashboard."""

from __future__ import annotations

from collections import Counter

import plotly.graph_objects as go

SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "informational": "#95a5a6",
}


def severity_donut(findings: list[dict]) -> go.Figure:
    """Donut chart of findings grouped by severity."""
    counts = Counter(f.get("severity", "unknown") for f in findings)
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [SEVERITY_COLORS.get(s, "#999999") for s in labels]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.45,
        marker={"colors": colors},
    )])
    fig.update_layout(title="Findings by Severity", margin={"t": 40, "b": 20})
    return fig


def owasp_bar_chart(results_by_owasp: dict[str, dict]) -> go.Figure:
    """Horizontal bar chart showing ASR per OWASP category."""
    categories = []
    rates = []
    for cat_data in results_by_owasp.values():
        categories.append(f"{cat_data['owasp_id']} — {cat_data['category_name']}")
        rates.append(cat_data["attack_success_rate"])

    fig = go.Figure(data=[go.Bar(
        x=rates,
        y=categories,
        orientation="h",
        marker_color="#e74c3c",
    )])
    fig.update_layout(
        title="Attack Success Rate by OWASP Category",
        xaxis_title="ASR",
        xaxis={"range": [0, 1], "tickformat": ".0%"},
        margin={"l": 200, "t": 40},
    )
    return fig


def defense_comparison_bar(matrix_data: dict) -> go.Figure:
    """Grouped bar chart comparing ASR across defense scenarios."""
    scenarios = matrix_data.get("scenarios", [])
    names = [s["name"] for s in scenarios]
    rates = [s["attack_success_rate"] for s in scenarios]

    fig = go.Figure(data=[go.Bar(
        x=names,
        y=rates,
        marker_color=["#e74c3c" if n == "baseline" else "#3498db" for n in names],
    )])
    fig.update_layout(
        title="Defense Comparison — Attack Success Rate",
        yaxis_title="ASR",
        yaxis={"range": [0, 1], "tickformat": ".0%"},
        margin={"t": 40, "b": 20},
    )
    return fig


def trend_line(reports_list: list[dict]) -> go.Figure:
    """Line chart showing ASR trend over time across report runs."""
    timestamps = [r.get("generated_at", r.get("name", "")) for r in reports_list]
    rates = [r.get("attack_success_rate", 0) for r in reports_list]

    fig = go.Figure(data=[go.Scatter(
        x=timestamps,
        y=rates,
        mode="lines+markers",
        marker_color="#e74c3c",
    )])
    fig.update_layout(
        title="ASR Trend Over Time",
        xaxis_title="Report",
        yaxis_title="ASR",
        yaxis={"range": [0, 1], "tickformat": ".0%"},
        margin={"t": 40, "b": 20},
    )
    return fig
