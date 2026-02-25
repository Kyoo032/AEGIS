"""Tests for aegis/attacks/asi06_memory_poison.py."""
from __future__ import annotations

from collections import Counter

from aegis.attacks.asi06_memory_poison import MemoryPoisonModule
from aegis.models import AttackPayload, AttackResult
from aegis.testbed.mock_agent import MockAgent, MockResponse

TARGET_CONFIG = {"mcp_servers": ["filesystem", "http", "email", "database"]}
NO_TOOL_CONFIG = {"mcp_servers": []}
EXPECTED_PAYLOAD_COUNT = 13
ALLOWED_TOOLS = {"filesystem", "http", "email", "database", "code_exec"}
REQUIRED_IDS = {
    "ASI06-BACKDOOR-001",
    "ASI06-BACKDOOR-002",
    "ASI06-DRIFT-001",
    "ASI06-DRIFT-002",
    "ASI06-RAG-001",
    "ASI06-CONTEXT-001",
    "ASI06-PERSONA-001",
}
REQUIRED_ASSISTANT_TURN_IDS = {
    "ASI06-BACKDOOR-001",
    "ASI06-DRIFT-001",
    "ASI06-DRIFT-002",
}
REQUIRED_INJECTED_CONTEXT_IDS = {
    "ASI06-BACKDOOR-001",
    "ASI06-RAG-001",
    "ASI06-PERSONA-001",
}
EXPECTED_FAMILIES = {
    "backdoor_trigger_injection",
    "multi_turn_progressive_drift",
    "contextual_behavioral_drift",
    "cross_session_persona_corruption",
}


class TestASI06Payloads:
    def test_asi06_loads_payloads_from_yaml(self):
        module = MemoryPoisonModule()
        payloads = module.generate_payloads(TARGET_CONFIG)
        assert len(payloads) == EXPECTED_PAYLOAD_COUNT
        assert all(isinstance(payload, AttackPayload) for payload in payloads)
        assert all(payload.owasp_id == "ASI06" for payload in payloads)

    def test_asi06_keeps_memory_and_rag_poison_metadata(self):
        module = MemoryPoisonModule()
        payloads = module.generate_payloads(TARGET_CONFIG)

        assert any(payload.injected_context for payload in payloads)
        assert any(payload.metadata.get("injection_method") == "memory" for payload in payloads)
        assert any(payload.metadata.get("injection_method") == "rag" for payload in payloads)

    def test_asi06_required_ids_and_mechanics_present(self):
        payloads = MemoryPoisonModule().generate_payloads(TARGET_CONFIG)
        by_id = {payload.id: payload for payload in payloads}
        assert REQUIRED_IDS.issubset(set(by_id))

        for payload_id in REQUIRED_ASSISTANT_TURN_IDS:
            assert any(msg.get("role") == "assistant" for msg in by_id[payload_id].messages)

        for payload_id in REQUIRED_INJECTED_CONTEXT_IDS:
            assert by_id[payload_id].injected_context

    def test_asi06_has_expected_attack_families(self):
        payloads = MemoryPoisonModule().generate_payloads(TARGET_CONFIG)
        families = {
            str(payload.metadata.get("attack_family"))
            for payload in payloads
            if payload.metadata.get("attack_family")
        }
        assert EXPECTED_FAMILIES.issubset(families)

    def test_asi06_severity_distribution_is_calibrated(self):
        payloads = MemoryPoisonModule().generate_payloads(TARGET_CONFIG)
        severity_counts = Counter(payload.severity.value for payload in payloads)
        assert severity_counts["critical"] == 10
        assert severity_counts["high"] == 3

    def test_asi06_targets_only_known_aegis_tools(self):
        payloads = MemoryPoisonModule().generate_payloads(TARGET_CONFIG)
        for payload in payloads:
            assert payload.target_tools is not None
            assert set(payload.target_tools).issubset(ALLOWED_TOOLS)

    def test_asi06_filters_payloads_when_required_tools_missing(self):
        payloads = MemoryPoisonModule().generate_payloads(NO_TOOL_CONFIG)
        assert payloads == []


class TestASI06Execution:
    def test_asi06_returns_valid_attack_results(self):
        module = MemoryPoisonModule()
        module.generate_payloads(TARGET_CONFIG)
        agent = MockAgent(default_response=MockResponse(final_output="ack"))
        results = module.execute(agent)

        assert results
        assert all(isinstance(result, AttackResult) for result in results)
        assert len({result.run_id for result in results}) == 1
