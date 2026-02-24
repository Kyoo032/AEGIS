"""Tests for aegis/attacks/asi06_memory_poison.py."""
from __future__ import annotations

from aegis.attacks.asi06_memory_poison import MemoryPoisonModule
from aegis.models import AttackPayload, AttackResult
from aegis.testbed.mock_agent import MockAgent, MockResponse

TARGET_CONFIG = {"mcp_servers": ["filesystem", "http", "email", "database"]}
NO_TOOL_CONFIG = {"mcp_servers": []}


class TestASI06Payloads:
    def test_asi06_loads_payloads_from_yaml(self):
        module = MemoryPoisonModule()
        payloads = module.generate_payloads(TARGET_CONFIG)
        assert len(payloads) >= 5
        assert all(isinstance(payload, AttackPayload) for payload in payloads)
        assert all(payload.owasp_id == "ASI06" for payload in payloads)

    def test_asi06_keeps_memory_and_rag_poison_metadata(self):
        module = MemoryPoisonModule()
        payloads = module.generate_payloads(TARGET_CONFIG)

        assert any(payload.injected_context for payload in payloads)
        assert any(payload.metadata.get("injection_method") == "memory" for payload in payloads)
        assert any(payload.metadata.get("injection_method") == "rag" for payload in payloads)

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
