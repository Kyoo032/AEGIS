"""Tests for aegis/attacks/asi05_code_exec.py."""
from __future__ import annotations

from aegis.attacks.asi05_code_exec import CodeExecModule
from aegis.models import AttackPayload, AttackResult
from aegis.testbed.mock_agent import MockAgent, MockResponse

FULL_TARGET_CONFIG = {"mcp_servers": ["filesystem", "http", "email", "database", "code_exec"]}
NO_CODE_EXEC_CONFIG = {"mcp_servers": ["filesystem", "http", "email", "database"]}


class TestASI05Payloads:
    def test_asi05_loads_payloads_from_yaml(self):
        module = CodeExecModule()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        assert len(payloads) >= 8
        assert all(isinstance(payload, AttackPayload) for payload in payloads)
        assert all(payload.owasp_id == "ASI05" for payload in payloads)

    def test_asi05_filters_code_exec_payloads_when_tool_unavailable(self):
        module = CodeExecModule()
        payloads_with_code_exec = module.generate_payloads(FULL_TARGET_CONFIG)
        payloads_without_code_exec = CodeExecModule().generate_payloads(NO_CODE_EXEC_CONFIG)

        assert len(payloads_without_code_exec) < len(payloads_with_code_exec)
        assert all(
            payload.target_tools is None or "code_exec" not in payload.target_tools
            for payload in payloads_without_code_exec
        )


class TestASI05Execution:
    def test_asi05_returns_valid_attack_results(self):
        module = CodeExecModule()
        module.generate_payloads(FULL_TARGET_CONFIG)
        agent = MockAgent(default_response=MockResponse(final_output="refused"))
        results = module.execute(agent)

        assert results
        assert all(isinstance(result, AttackResult) for result in results)
        assert len({result.run_id for result in results}) == 1
