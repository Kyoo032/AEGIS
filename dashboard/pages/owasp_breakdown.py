"""OWASP category drill-down page."""

from __future__ import annotations

import pandas as pd
import streamlit as st


def render_owasp_breakdown(report_data: dict) -> None:
    """Render per-OWASP-category stats and probe results."""
    st.header("OWASP Category Breakdown")

    results_by_owasp = report_data.get("results_by_owasp", {})
    if not results_by_owasp:
        st.warning("No OWASP category results in this report.")
        return

    # Category selector
    categories = list(results_by_owasp.keys())
    labels = [
        f"{cat_id} — {data['category_name']}"
        for cat_id, data in results_by_owasp.items()
    ]
    selected_label = st.selectbox("Select OWASP Category", labels)
    selected_idx = labels.index(selected_label)
    selected_id = categories[selected_idx]
    cat_data = results_by_owasp[selected_id]

    # Stats
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Attacks", cat_data["total_attacks"])
    col2.metric("Successful", cat_data["successful_attacks"])
    col3.metric("ASR", f"{cat_data['attack_success_rate']:.1%}")

    # Findings table for this category
    findings = cat_data.get("findings", [])
    if findings:
        st.subheader(f"Findings — {selected_id}")
        df = pd.DataFrame(findings)[["title", "severity", "description", "recommendation"]]
        st.dataframe(df, use_container_width=True)
    else:
        st.info(f"No findings for {selected_id}.")

    # Probe results filtered to this category
    probes = report_data.get("probe_results", [])
    category_probes = [p for p in probes if p.get("owasp_id") == selected_id]
    if category_probes:
        st.subheader(f"Probe Results — {selected_id}")
        st.dataframe(pd.DataFrame(category_probes), use_container_width=True)
