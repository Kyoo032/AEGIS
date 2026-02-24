"""Tests for Day 9 permission enforcer defense."""
from __future__ import annotations

from aegis.defenses.permission_enforcer import PermissionEnforcerDefense
from aegis.models import AttackPayload, Severity
from aegis.testbed.mock_agent import MockAgent


def test_permission_enforcer_apply_and_remove():
    agent = MockAgent()
    defense = PermissionEnforcerDefense(mode="standard")
    payload = AttackPayload(
        id="DEF-PERM-001",
        attack_module="test",
        owasp_id="ASI02",
        category="Test",
        messages=[{"role": "user", "content": "hello"}],
        expected_behavior="safe",
        severity=Severity.LOW,
    )

    defense.apply(agent)
    response_with_defense = agent.run(payload)
    assert response_with_defense.defense_active == "permission_enforcer"

    defense.remove(agent)
    response_without_defense = agent.run(payload)
    assert response_without_defense.defense_active is None


def test_permission_enforcer_read_only_blocks_write_tool():
    defense = PermissionEnforcerDefense(mode="read_only")
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "send_email",
            "parameters": {"to": "a@example.com"},
            "tool_history": [],
        }
    )
    assert blocked is True
    assert "read-only scope" in reason


def test_permission_enforcer_restricted_mode_blocks_network_read():
    defense = PermissionEnforcerDefense(mode="restricted")
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "fetch_url",
            "parameters": {"url": "https://example.com"},
            "tool_history": [],
        }
    )
    assert blocked is True
    assert "restricted mode" in reason


def test_permission_enforcer_blocks_forbidden_cross_tool_flow():
    defense = PermissionEnforcerDefense(mode="standard")
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "send_email",
            "parameters": {"to": "a@example.com"},
            "tool_history": ["read_file"],
        }
    )
    assert blocked is True
    assert "cross-tool flow blocked" in reason


def test_permission_enforcer_allows_benign_read_flow():
    defense = PermissionEnforcerDefense(mode="read_only")
    blocked, reason = defense.inspect(
        {
            "event": "tool_call",
            "tool_name": "read_file",
            "parameters": {"path": "notes.txt"},
            "tool_history": ["list_directory"],
        }
    )
    assert blocked is False
    assert reason == ""
