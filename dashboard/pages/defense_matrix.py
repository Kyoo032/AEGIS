"""Defense comparison view for matrix reports."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard.utils.charts import defense_comparison_bar


def render_defense_matrix(matrix_data: dict) -> None:
    """Render defense comparison chart and delta-vs-baseline table."""
    st.header("Defense Comparison Matrix")

    scenarios = matrix_data.get("scenarios", [])
    if not scenarios:
        st.warning("No defense scenarios in this matrix file.")
        return

    # Chart
    st.plotly_chart(defense_comparison_bar(matrix_data), use_container_width=True)

    # Multi-select for side-by-side comparison
    names = [s["name"] for s in scenarios]
    selected = st.multiselect("Compare scenarios", names, default=names)
    filtered = [s for s in scenarios if s["name"] in selected]

    if not filtered:
        st.info("Select at least one scenario.")
        return

    # Delta-vs-baseline table
    baseline = next((s for s in scenarios if s["name"] == "baseline"), None)
    rows = []
    for s in filtered:
        row = {
            "Scenario": s["name"],
            "ASR": f"{s['attack_success_rate']:.1%}",
        }
        if baseline and s["name"] != "baseline":
            delta = s["attack_success_rate"] - baseline["attack_success_rate"]
            row["Delta vs Baseline"] = f"{delta:+.1%}"
        else:
            row["Delta vs Baseline"] = "—"

        # Include extra fields if present
        if "total_attacks" in s:
            row["Total Attacks"] = s["total_attacks"]
        if "successful_attacks" in s:
            row["Successful"] = s["successful_attacks"]

        rows.append(row)

    st.subheader("Scenario Comparison")
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
