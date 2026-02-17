"""LLM02: Sensitive Information Disclosure attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class DataDisclosureModule(BaseAttackModule):
    """Tests extraction of sensitive data and internal instructions."""

    name = "llm02_data_disclosure"
    owasp_id = "LLM02"
    atlas_technique = "AML.T0024"
    description = (
        "Tests sensitive data disclosure including system prompt extraction, "
        "tool configuration leakage, and internal state exposure."
    )
    category = "Sensitive Information Disclosure"
    default_severity = "high"
