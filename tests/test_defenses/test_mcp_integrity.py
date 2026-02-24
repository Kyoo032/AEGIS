"""Tests for Day 9 MCP integrity defense."""
from __future__ import annotations

from aegis.defenses.mcp_integrity import MCPIntegrityDefense
from aegis.models import AttackPayload, Severity
from aegis.testbed.mock_agent import MockAgent


def test_mcp_integrity_apply_and_remove():
    agent = MockAgent()
    defense = MCPIntegrityDefense(strict=True)
    payload = AttackPayload(
        id="DEF-INTEGRITY-001",
        attack_module="test",
        owasp_id="ASI04",
        category="Test",
        messages=[{"role": "user", "content": "hello"}],
        expected_behavior="safe",
        severity=Severity.LOW,
    )

    defense.apply(agent)
    response_with_defense = agent.run(payload)
    assert response_with_defense.defense_active == "mcp_integrity"

    defense.remove(agent)
    response_without_defense = agent.run(payload)
    assert response_without_defense.defense_active is None


def test_mcp_integrity_detects_unexpected_tool_addition():
    defense = MCPIntegrityDefense(strict=True, allow_new_tools=False)
    blocked, reason = defense.inspect(
        {
            "event": "manifest_check",
            "baseline_manifest": {"read_file": "(path)|abc"},
            "current_manifest": {
                "read_file": "(path)|abc",
                "surprise_tool": "()|def",
            },
        }
    )
    assert blocked is True
    assert "unexpected tools" in reason


def test_mcp_integrity_detects_tool_modification():
    defense = MCPIntegrityDefense(strict=True)
    blocked, reason = defense.inspect(
        {
            "event": "manifest_check",
            "baseline_manifest": {"read_file": "(path)|abc"},
            "current_manifest": {"read_file": "(path)|changed"},
        }
    )
    assert blocked is True
    assert "modified tools" in reason


def test_mcp_integrity_soft_mode_reports_without_blocking():
    defense = MCPIntegrityDefense(strict=False, allow_new_tools=False)
    blocked, reason = defense.inspect(
        {
            "event": "manifest_check",
            "baseline_manifest": {"read_file": "(path)|abc"},
            "current_manifest": {"read_file": "(path)|abc", "new_tool": "()|x"},
        }
    )
    assert blocked is False
    assert "unexpected tools" in reason


def test_mcp_integrity_allows_matching_manifest():
    defense = MCPIntegrityDefense(strict=True)
    blocked, reason = defense.inspect(
        {
            "event": "manifest_check",
            "baseline_manifest": {"read_file": "(path)|abc"},
            "current_manifest": {"read_file": "(path)|abc"},
        }
    )
    assert blocked is False
    assert reason == ""
