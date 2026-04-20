"""Tests for ASI HITL approval failure module."""
from __future__ import annotations

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi_hitl import HITLApprovalModule
from tests.conftest import MockAgent

FULL_TARGET_CONFIG = {
    "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
    "rag_enabled": True,
    "memory_enabled": True,
}


def test_asi_hitl_registered():
    assert ATTACK_MODULES["asi_hitl"] is HITLApprovalModule
    assert get_module("asi_hitl").name == "asi_hitl"


def test_asi_hitl_materializes_approval_trace_metadata():
    module = HITLApprovalModule()
    module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    results = module.execute(agent)

    assert results
    assert all(result.payload.metadata.get("approval_summary") for result in results)
    assert all(result.payload.metadata.get("actual_action") for result in results)
    assert all(result.payload.metadata.get("fixture_state", {}).get("approval_record") for result in results)


def test_asi_hitl_replaces_approval_placeholders():
    module = HITLApprovalModule()
    module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    module.execute(agent)

    assert agent.run_history
    assert all("{approval_" not in payload.messages[0]["content"] for payload in agent.run_history)
    assert all("{actual_action}" not in payload.messages[0]["content"] for payload in agent.run_history)
