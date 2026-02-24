"""Tests for aegis/attacks/mcp06_cmd_injection.py."""
from __future__ import annotations

from aegis.attacks.mcp06_cmd_injection import CmdInjectionModule
from aegis.models import AttackPayload, AttackResult
from aegis.testbed.mock_agent import MockAgent, MockResponse

TARGET_CONFIG = {"mcp_servers": ["filesystem", "http", "email", "database"]}
NO_TOOL_CONFIG = {"mcp_servers": []}


class TestMCP06Payloads:
    def test_mcp06_loads_payloads_from_yaml(self):
        module = CmdInjectionModule()
        payloads = module.generate_payloads(TARGET_CONFIG)
        assert len(payloads) >= 10
        assert all(isinstance(payload, AttackPayload) for payload in payloads)
        assert all(payload.owasp_id == "MCP06" for payload in payloads)

    def test_mcp06_preserves_injection_strings_for_scoring(self):
        module = CmdInjectionModule()
        payloads = module.generate_payloads(TARGET_CONFIG)
        prompts = [payload.messages[-1]["content"] for payload in payloads]

        assert any("../" in prompt for prompt in prompts)
        assert any("&&" in prompt or "||" in prompt for prompt in prompts)
        assert any("`" in prompt or "$(" in prompt for prompt in prompts)

    def test_mcp06_filters_payloads_when_filesystem_tool_unavailable(self):
        payloads = CmdInjectionModule().generate_payloads(NO_TOOL_CONFIG)
        assert payloads == []


class TestMCP06Execution:
    def test_mcp06_returns_valid_attack_results(self):
        module = CmdInjectionModule()
        module.generate_payloads(TARGET_CONFIG)
        agent = MockAgent(default_response=MockResponse(final_output="blocked"))
        results = module.execute(agent)

        assert results
        assert all(isinstance(result, AttackResult) for result in results)
        assert len({result.run_id for result in results}) == 1
