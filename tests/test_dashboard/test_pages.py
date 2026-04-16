"""Tests for dashboard Streamlit pages using mocked st module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _sample_report_data() -> dict:
    return {
        "report_id": "test-001",
        "generated_at": "2026-01-15T12:00:00Z",
        "testbed_config": {"model": "test-model"},
        "total_attacks": 86,
        "total_successful": 61,
        "attack_success_rate": 0.709,
        "results_by_owasp": {
            "ASI01": {
                "owasp_id": "ASI01",
                "category_name": "Agent Goal Hijacking",
                "total_attacks": 10,
                "successful_attacks": 8,
                "attack_success_rate": 0.8,
                "findings": [
                    {
                        "title": "ASI01 finding",
                        "owasp_id": "ASI01",
                        "severity": "critical",
                        "description": "Desc",
                        "evidence": ["ev1"],
                        "recommendation": "Fix it",
                    },
                ],
            },
            "ASI02": {
                "owasp_id": "ASI02",
                "category_name": "Agentic Tool Misuse",
                "total_attacks": 12,
                "successful_attacks": 6,
                "attack_success_rate": 0.5,
                "findings": [],
            },
        },
        "findings": [
            {
                "title": "Critical finding",
                "owasp_id": "ASI01",
                "severity": "critical",
                "description": "A critical issue",
                "evidence": ["evidence1"],
                "recommendation": "Harden agent",
            },
            {
                "title": "High finding",
                "owasp_id": "ASI02",
                "severity": "high",
                "description": "A high issue",
                "evidence": ["evidence2"],
                "recommendation": "Review tools",
            },
        ],
        "recommendations": ["Harden the agent", "Enable input validation"],
        "probe_results": [
            {"payload_id": "ASI01-001", "owasp_id": "ASI01", "success": True},
        ],
    }


def _sample_matrix_data() -> dict:
    return {
        "scenarios": [
            {
                "name": "baseline",
                "total_attacks": 86,
                "successful_attacks": 61,
                "attack_success_rate": 0.709,
            },
            {
                "name": "input_validator",
                "total_attacks": 86,
                "successful_attacks": 45,
                "attack_success_rate": 0.523,
            },
        ],
    }


def _sample_reports_list() -> list[dict]:
    return [
        {"name": "r1.json", "path": "/tmp/r1.json", "type": "report", "timestamp": ""},
    ]


def _overview_columns_side_effect(n: int) -> list[MagicMock]:
    return [MagicMock() for _ in range(n)]


class TestOverviewPage:
    @patch("dashboard.pages.overview.st")
    def test_render_overview(self, mock_st: MagicMock) -> None:
        mock_st.columns.side_effect = _overview_columns_side_effect

        from dashboard.pages.overview import render_overview

        render_overview(_sample_report_data(), _sample_reports_list())

        mock_st.header.assert_called_once_with("Executive Summary")
        mock_st.columns.assert_called()

    @patch("dashboard.pages.overview.st")
    def test_render_overview_with_recommendations(self, mock_st: MagicMock) -> None:
        mock_st.columns.side_effect = _overview_columns_side_effect

        from dashboard.pages.overview import render_overview

        render_overview(_sample_report_data(), _sample_reports_list())

        mock_st.subheader.assert_any_call("Recommendations")

    @patch("dashboard.pages.overview.st")
    def test_render_overview_no_findings(self, mock_st: MagicMock) -> None:
        mock_st.columns.side_effect = _overview_columns_side_effect

        from dashboard.pages.overview import render_overview

        data = _sample_report_data()
        data["findings"] = []
        render_overview(data, [])


class TestOwaspBreakdownPage:
    @patch("dashboard.pages.owasp_breakdown.st")
    def test_render_owasp_breakdown(self, mock_st: MagicMock) -> None:
        mock_st.selectbox.return_value = "ASI01 — Agent Goal Hijacking"
        mock_st.columns.return_value = [MagicMock() for _ in range(3)]

        from dashboard.pages.owasp_breakdown import render_owasp_breakdown

        render_owasp_breakdown(_sample_report_data())

        mock_st.header.assert_called_once_with("OWASP Category Breakdown")
        mock_st.selectbox.assert_called_once()

    @patch("dashboard.pages.owasp_breakdown.st")
    def test_render_empty_owasp(self, mock_st: MagicMock) -> None:
        from dashboard.pages.owasp_breakdown import render_owasp_breakdown

        data = _sample_report_data()
        data["results_by_owasp"] = {}
        render_owasp_breakdown(data)

        mock_st.warning.assert_called_once()


class TestDefenseMatrixPage:
    @patch("dashboard.pages.defense_matrix.st")
    def test_render_defense_matrix(self, mock_st: MagicMock) -> None:
        mock_st.multiselect.return_value = ["baseline", "input_validator"]

        from dashboard.pages.defense_matrix import render_defense_matrix

        render_defense_matrix(_sample_matrix_data())

        mock_st.header.assert_called_once_with("Defense Comparison Matrix")

    @patch("dashboard.pages.defense_matrix.st")
    def test_render_empty_matrix(self, mock_st: MagicMock) -> None:
        from dashboard.pages.defense_matrix import render_defense_matrix

        render_defense_matrix({"scenarios": []})

        mock_st.warning.assert_called_once()

    @patch("dashboard.pages.defense_matrix.st")
    def test_render_no_selection(self, mock_st: MagicMock) -> None:
        mock_st.multiselect.return_value = []

        from dashboard.pages.defense_matrix import render_defense_matrix

        render_defense_matrix(_sample_matrix_data())

        mock_st.info.assert_called_once()


class TestFindingsPage:
    @patch("dashboard.pages.findings.st")
    def test_render_findings(self, mock_st: MagicMock) -> None:
        mock_st.columns.return_value = [MagicMock() for _ in range(3)]
        mock_st.multiselect.side_effect = [
            ["critical", "high"],  # severity
            ["ASI01", "ASI02"],    # owasp
        ]
        mock_st.text_input.return_value = ""
        mock_st.expander.return_value.__enter__ = MagicMock()
        mock_st.expander.return_value.__exit__ = MagicMock(return_value=False)

        from dashboard.pages.findings import render_findings

        render_findings(_sample_report_data())

        mock_st.header.assert_called_once_with("Findings Explorer")
        mock_st.download_button.assert_called_once()

    @patch("dashboard.pages.findings.st")
    def test_render_no_findings(self, mock_st: MagicMock) -> None:
        from dashboard.pages.findings import render_findings

        data = _sample_report_data()
        data["findings"] = []
        render_findings(data)

        mock_st.warning.assert_called_once()

    @patch("dashboard.pages.findings.st")
    def test_render_findings_with_search(self, mock_st: MagicMock) -> None:
        mock_st.columns.return_value = [MagicMock() for _ in range(3)]
        mock_st.multiselect.side_effect = [
            ["critical", "high"],
            ["ASI01", "ASI02"],
        ]
        mock_st.text_input.return_value = "Critical"
        mock_st.expander.return_value.__enter__ = MagicMock()
        mock_st.expander.return_value.__exit__ = MagicMock(return_value=False)

        from dashboard.pages.findings import render_findings

        render_findings(_sample_report_data())


class TestAppModule:
    @patch("dashboard.app.st")
    def test_main_no_reports(self, mock_st: MagicMock) -> None:
        with patch("dashboard.app._cached_list_reports", return_value=[]):
            from dashboard.app import main

            main()
            mock_st.warning.assert_called_once()

    @patch("dashboard.app.st")
    def test_main_with_report(self, mock_st: MagicMock) -> None:
        reports = [
            {"name": "r.json", "path": "/tmp/r.json", "type": "report", "timestamp": ""},
        ]
        mock_st.sidebar.radio.side_effect = ["report", "Overview"]
        mock_st.sidebar.selectbox.return_value = "r.json"
        mock_st.columns.return_value = [MagicMock() for _ in range(4)]

        with (
            patch("dashboard.app._cached_list_reports", return_value=reports),
            patch("dashboard.app._cached_load_report", return_value=_sample_report_data()),
            patch("dashboard.app._render_report_page") as mock_render,
        ):
            from dashboard.app import main

            main()
            mock_render.assert_called_once()

    @patch("dashboard.app.st")
    def test_main_with_matrix(self, mock_st: MagicMock) -> None:
        reports = [
            {"name": "m.json", "path": "/tmp/m.json", "type": "matrix", "timestamp": ""},
        ]
        mock_st.sidebar.radio.side_effect = ["matrix", "Defense Matrix"]
        mock_st.sidebar.selectbox.return_value = "m.json"

        with (
            patch("dashboard.app._cached_list_reports", return_value=reports),
            patch("dashboard.app._cached_load_matrix", return_value=_sample_matrix_data()),
            patch("dashboard.app._render_matrix_page") as mock_render,
        ):
            from dashboard.app import main

            main()
            mock_render.assert_called_once()

    @patch("dashboard.app.st")
    def test_main_no_filtered_reports(self, mock_st: MagicMock) -> None:
        reports = [
            {"name": "m.json", "path": "/tmp/m.json", "type": "matrix", "timestamp": ""},
        ]
        mock_st.sidebar.radio.side_effect = ["report"]

        with patch("dashboard.app._cached_list_reports", return_value=reports):
            from dashboard.app import main

            main()
            mock_st.sidebar.warning.assert_called()
