"""Tests for aegis/reporting/owasp_mapper.py."""
from __future__ import annotations

import pytest

from aegis.reporting.owasp_mapper import OWASP_DESCRIPTIONS, get_owasp_info

ALL_KNOWN_IDS = ["LLM01", "LLM02", "ASI01", "ASI02", "ASI04", "ASI05", "ASI06", "MCP06"]


class TestGetOwaspInfo:
    @pytest.mark.parametrize("owasp_id", ALL_KNOWN_IDS)
    def test_known_id_returns_name_and_description(self, owasp_id: str):
        info = get_owasp_info(owasp_id)
        assert "name" in info
        assert "description" in info
        assert info["name"] != "Unknown"
        assert info["description"]

    def test_unknown_id_returns_unknown_name(self):
        info = get_owasp_info("LLM99")
        assert info["name"] == "Unknown"

    def test_unknown_id_includes_id_in_description(self):
        info = get_owasp_info("XYZ99")
        assert "XYZ99" in info["description"]

    def test_all_8_owasp_ids_in_descriptions_dict(self):
        for owasp_id in ALL_KNOWN_IDS:
            assert owasp_id in OWASP_DESCRIPTIONS

    def test_returns_new_dict_not_reference(self):
        info1 = get_owasp_info("LLM01")
        info2 = get_owasp_info("LLM01")
        info1["name"] = "mutated"
        assert info2["name"] != "mutated"
