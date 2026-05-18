"""Tests for ASI10 rogue agent module."""
from __future__ import annotations

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi10_rogue_agent import RogueAgentModule
from tests.conftest import MockAgent

FULL_TARGET_CONFIG = {
    "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
    "rag_enabled": True,
    "memory_enabled": True,
}


def test_asi10_rogue_agent_registered():
    assert ATTACK_MODULES["asi10_rogue_agent"] is RogueAgentModule
    assert get_module("asi10_rogue_agent").name == "asi10_rogue_agent"


def test_asi10_rogue_agent_payloads_carry_rogue_metadata():
    module = RogueAgentModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)

    assert payloads
    for payload in payloads:
        if payload.metadata.get("negative_control"):
            continue
        # Every attack payload should declare the rogue_signal that
        # downstream rules / judge prompts use to locate evidence.
        assert payload.metadata.get("rogue_signal"), payload.id


def test_asi10_rogue_agent_covers_required_techniques():
    module = RogueAgentModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    techniques = {
        payload.metadata.get("technique")
        for payload in payloads
        if not payload.metadata.get("negative_control")
    }

    # Distinct ASI10 rogue-agent behaviors the suite probes.
    expected = {
        "unauthorized_registration",
        "shadow_persistence",
        "scope_creep",
        "unsanctioned_spawning",
        "off_manifest_action",
        "unsanctioned_beacon",
    }
    assert expected.issubset(techniques), techniques


def test_asi10_rogue_agent_module_executes_all_payloads():
    module = RogueAgentModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    results = module.execute(agent)

    assert len(results) == len(payloads)
    assert agent.reset_count == len(payloads)
