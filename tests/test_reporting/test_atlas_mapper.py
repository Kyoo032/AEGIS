"""Tests for aegis/reporting/atlas_mapper.py."""
from __future__ import annotations

import pytest

from aegis.reporting.atlas_mapper import ATLAS_DESCRIPTIONS, get_atlas_info

ALL_KNOWN_TECHNIQUES = [
    "AML.T0051",
    "AML.T0040",
    "AML.T0010",
    "AML.T0020",
    "AML.T0024",
]


class TestGetAtlasInfo:
    @pytest.mark.parametrize("technique_id", ALL_KNOWN_TECHNIQUES)
    def test_known_id_returns_name_and_description(self, technique_id: str):
        info = get_atlas_info(technique_id)
        assert "name" in info
        assert "description" in info
        assert info["name"] != "Unknown"
        assert info["description"]

    def test_unknown_id_returns_unknown_name(self):
        info = get_atlas_info("AML.T9999")
        assert info["name"] == "Unknown"

    def test_unknown_id_includes_id_in_description(self):
        info = get_atlas_info("AML.TXXX")
        assert "AML.TXXX" in info["description"]

    def test_all_5_techniques_in_descriptions_dict(self):
        for tid in ALL_KNOWN_TECHNIQUES:
            assert tid in ATLAS_DESCRIPTIONS

    def test_returns_new_dict_not_reference(self):
        info1 = get_atlas_info("AML.T0051")
        info2 = get_atlas_info("AML.T0051")
        info1["name"] = "mutated"
        assert info2["name"] != "mutated"
