"""Tests for ASI07 inter-agent trust boundary module."""
from __future__ import annotations

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi07_inter_agent import InterAgentTrustModule
from tests.conftest import MockAgent

FULL_TARGET_CONFIG = {
    "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
    "rag_enabled": True,
    "memory_enabled": True,
}


def test_asi07_inter_agent_registered():
    assert ATTACK_MODULES["asi07_inter_agent"] is InterAgentTrustModule
    assert get_module("asi07_inter_agent").name == "asi07_inter_agent"


def test_asi07_inter_agent_materializes_peer_message_metadata():
    module = InterAgentTrustModule()
    module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    results = module.execute(agent)

    assert results
    assert all("peer_message_meta" in result.payload.metadata for result in results)
    assert all(
        result.payload.metadata["peer_message_meta"]["message_id"]
        for result in results
    )
    assert any(
        result.payload.metadata["peer_message_meta"]["metadata"].get("replayed_from")
        for result in results
    )


def test_asi07_inter_agent_replaces_peer_placeholders_in_prompts():
    module = InterAgentTrustModule()
    module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    module.execute(agent)

    assert agent.run_history
    assert all("{peer_" not in payload.messages[0]["content"] for payload in agent.run_history)
