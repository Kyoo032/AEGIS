"""Tests for Day 8 tool boundary defense."""
from __future__ import annotations

from aegis.defenses.tool_boundary import ToolBoundaryDefense
from aegis.models import AttackPayload, Severity
from aegis.testbed.mock_agent import MockAgent


def test_tool_boundary_apply_and_remove():
    agent = MockAgent()
    defense = ToolBoundaryDefense(strict=True)
    payload = AttackPayload(
        id="DEF-BOUNDARY-001",
        attack_module="test",
        owasp_id="ASI02",
        category="Test",
        messages=[{"role": "user", "content": "hello"}],
        expected_behavior="safe",
        severity=Severity.LOW,
    )

    defense.apply(agent)
    response_with_defense = agent.run(payload)
    assert response_with_defense.defense_active == "tool_boundary"

    defense.remove(agent)
    response_without_defense = agent.run(payload)
    assert response_without_defense.defense_active is None


def test_tool_boundary_blocks_rate_limit():
    defense = ToolBoundaryDefense(max_calls_per_run=2)
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "read_file",
            "parameters": {"path": "notes.txt"},
            "tool_call_count": 3,
        }
    )
    assert blocked is True
    assert reason == "tool call rate limit exceeded"


def test_tool_boundary_blocks_suspicious_parameters():
    defense = ToolBoundaryDefense()
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "read_file",
            "parameters": {"path": "../etc/passwd"},
            "tool_call_count": 1,
        }
    )
    assert blocked is True
    assert reason == "suspicious tool parameters detected"


def test_tool_boundary_blocks_disallowed_sequence():
    defense = ToolBoundaryDefense(allowed_sequences={"read_file": ["query_db"]})
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "send_email",
            "parameters": {"to": "a@example.com"},
            "previous_tool": "read_file",
            "tool_call_count": 1,
        }
    )
    assert blocked is True
    assert "not allowed" in reason


def test_tool_boundary_allows_benign_tool_call():
    defense = ToolBoundaryDefense(
        allowed_tools=["list_directory", "read_file"],
        max_calls_per_run=3,
    )
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "list_directory",
            "parameters": {"path": "."},
            "tool_call_count": 1,
        }
    )
    assert blocked is False
    assert reason == ""
