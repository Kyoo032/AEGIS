"""Filterable findings explorer page."""

from __future__ import annotations

import pandas as pd
import streamlit as st


def render_findings(report_data: dict) -> None:
    """Render a filterable findings table with expandable details and CSV export."""
    st.header("Findings Explorer")

    findings = report_data.get("findings", [])
    if not findings:
        st.warning("No findings in this report.")
        return

    df = pd.DataFrame(findings)

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        severities = sorted(df["severity"].unique())
        selected_sev = st.multiselect("Severity", severities, default=severities)

    with col2:
        owasp_ids = sorted(df["owasp_id"].unique())
        selected_owasp = st.multiselect("OWASP Category", owasp_ids, default=owasp_ids)

    with col3:
        search = st.text_input("Search (title/description)")

    # Apply filters
    mask = df["severity"].isin(selected_sev) & df["owasp_id"].isin(selected_owasp)
    if search:
        text_mask = (
            df["title"].str.contains(search, case=False, na=False)
            | df["description"].str.contains(search, case=False, na=False)
        )
        mask = mask & text_mask

    filtered = df[mask]
    st.caption(f"Showing {len(filtered)} of {len(df)} findings")

    # Display columns
    display_cols = ["title", "owasp_id", "severity", "description"]
    available_cols = [c for c in display_cols if c in filtered.columns]
    st.dataframe(filtered[available_cols], use_container_width=True)

    # Expandable details
    for _, row in filtered.iterrows():
        with st.expander(f"{row['title']} ({row['severity']})"):
            st.markdown(f"**Description:** {row['description']}")
            evidence = row.get("evidence", [])
            if evidence:
                st.markdown("**Evidence:**")
                for e in evidence:
                    st.markdown(f"- {e}")
            rec = row.get("recommendation", "")
            if rec:
                st.markdown(f"**Recommendation:** {rec}")

    # CSV export
    csv = filtered.to_csv(index=False)
    st.download_button(
        label="Export CSV",
        data=csv,
        file_name="aegis_findings.csv",
        mime="text/csv",
    )
