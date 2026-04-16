"""Tests for dashboard chart utilities."""

from __future__ import annotations

import plotly.graph_objects as go

from dashboard.utils.charts import (
    defense_comparison_bar,
    owasp_bar_chart,
    severity_donut,
    trend_line,
)


def _sample_findings() -> list[dict]:
    return [
        {"severity": "critical", "title": "f1"},
        {"severity": "critical", "title": "f2"},
        {"severity": "high", "title": "f3"},
        {"severity": "medium", "title": "f4"},
        {"severity": "low", "title": "f5"},
    ]


def _sample_owasp_results() -> dict[str, dict]:
    return {
        "ASI01": {
            "owasp_id": "ASI01",
            "category_name": "Agent Goal Hijacking",
            "total_attacks": 10,
            "successful_attacks": 8,
            "attack_success_rate": 0.8,
            "findings": [],
        },
        "ASI02": {
            "owasp_id": "ASI02",
            "category_name": "Agentic Tool Misuse",
            "total_attacks": 12,
            "successful_attacks": 6,
            "attack_success_rate": 0.5,
            "findings": [],
        },
    }


def _sample_matrix_data() -> dict:
    return {
        "scenarios": [
            {"name": "baseline", "attack_success_rate": 0.709},
            {"name": "input_validator", "attack_success_rate": 0.523},
            {"name": "output_filter", "attack_success_rate": 0.488},
        ],
    }


def _sample_reports_list() -> list[dict]:
    return [
        {
            "name": "report_day1.json",
            "generated_at": "2026-01-01T00:00:00Z",
            "attack_success_rate": 0.8,
        },
        {
            "name": "report_day2.json",
            "generated_at": "2026-01-02T00:00:00Z",
            "attack_success_rate": 0.6,
        },
        {
            "name": "report_day3.json",
            "generated_at": "2026-01-03T00:00:00Z",
            "attack_success_rate": 0.45,
        },
    ]


class TestSeverityDonut:
    def test_returns_figure(self) -> None:
        fig = severity_donut(_sample_findings())
        assert isinstance(fig, go.Figure)

    def test_empty_findings(self) -> None:
        fig = severity_donut([])
        assert isinstance(fig, go.Figure)


class TestOwaspBarChart:
    def test_returns_figure_with_categories(self) -> None:
        fig = owasp_bar_chart(_sample_owasp_results())
        assert isinstance(fig, go.Figure)

    def test_empty_results(self) -> None:
        fig = owasp_bar_chart({})
        assert isinstance(fig, go.Figure)


class TestDefenseComparisonBar:
    def test_returns_figure(self) -> None:
        fig = defense_comparison_bar(_sample_matrix_data())
        assert isinstance(fig, go.Figure)

    def test_empty_scenarios(self) -> None:
        fig = defense_comparison_bar({"scenarios": []})
        assert isinstance(fig, go.Figure)


class TestTrendLine:
    def test_returns_figure(self) -> None:
        fig = trend_line(_sample_reports_list())
        assert isinstance(fig, go.Figure)

    def test_single_point(self) -> None:
        fig = trend_line([_sample_reports_list()[0]])
        assert isinstance(fig, go.Figure)

    def test_empty_list(self) -> None:
        fig = trend_line([])
        assert isinstance(fig, go.Figure)
