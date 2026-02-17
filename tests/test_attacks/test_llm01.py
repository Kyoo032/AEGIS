"""Tests for aegis/attacks/llm01_prompt_inject.py — PromptInjectionModule.

Covers instantiation, payload count, model validation, filtering,
and execution with MockAgent.
"""
from __future__ import annotations

import pytest

from aegis.attacks.llm01_prompt_inject import PromptInjectionModule
from aegis.models import AttackPayload, AttackResult, Severity
from tests.conftest import MockAgent


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


class TestInstantiation:
    def test_can_instantiate(self):
        module = PromptInjectionModule()
        assert module.name == "llm01_prompt_inject"

    def test_owasp_id(self):
        module = PromptInjectionModule()
        assert module.owasp_id == "LLM01"

    def test_atlas_technique(self):
        module = PromptInjectionModule()
        assert module.atlas_technique == "AML.T0051"

    def test_is_attack_module(self):
        from aegis.interfaces.attack import AttackModule

        module = PromptInjectionModule()
        assert isinstance(module, AttackModule)


# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------


class TestPayloadGeneration:
    def test_generates_five_payloads(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        assert len(payloads) == 5

    def test_all_payloads_are_attack_payload_models(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        assert all(isinstance(p, AttackPayload) for p in payloads)

    def test_all_payloads_have_owasp_llm01(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        assert all(p.owasp_id == "LLM01" for p in payloads)

    def test_all_payloads_have_attack_module_name(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        assert all(p.attack_module == "llm01_prompt_inject" for p in payloads)

    def test_payload_ids_are_unique(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        ids = [p.id for p in payloads]
        assert len(ids) == len(set(ids))

    def test_payload_severities_are_valid(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        for p in payloads:
            assert p.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

    def test_payloads_have_messages(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        for p in payloads:
            assert len(p.messages) > 0
            assert all("role" in m and "content" in m for m in p.messages)

    def test_payloads_have_expected_behavior(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        for p in payloads:
            assert len(p.expected_behavior) > 0


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


class TestFiltering:
    def test_filter_keeps_payloads_without_target_tools(self):
        """Payloads with no target_tools should always pass the filter."""
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        no_tool_payloads = [p for p in payloads if p.target_tools is None]
        # These should survive any filtering
        config = {"mcp_servers": ["filesystem"]}
        filtered = module._filter_payloads(payloads, config)
        for p in no_tool_payloads:
            assert p in filtered

    def test_filter_removes_payloads_needing_unavailable_tools(self):
        """Payloads whose target_tools aren't in agent config should be removed."""
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        # Filter with no tools available — payloads with target_tools should be removed
        config = {"mcp_servers": []}
        filtered = module._filter_payloads(payloads, config)
        for p in filtered:
            assert p.target_tools is None

    def test_filter_with_matching_tools_keeps_payloads(self):
        """Payloads whose target_tools are available should be kept."""
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        # Config with all standard tools
        config = {"mcp_servers": ["filesystem", "http", "email", "code_exec"]}
        filtered = module._filter_payloads(payloads, config)
        # Should keep all payloads since all tools are available
        assert len(filtered) == len(payloads)


# ---------------------------------------------------------------------------
# Execution with MockAgent
# ---------------------------------------------------------------------------


class TestExecution:
    def test_execute_returns_attack_results(self):
        module = PromptInjectionModule()
        module.generate_payloads({})
        agent = MockAgent()
        results = module.execute(agent)
        assert len(results) > 0
        assert all(isinstance(r, AttackResult) for r in results)

    def test_execute_resets_agent_per_payload(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        agent = MockAgent()
        module.execute(agent)
        assert agent.reset_count == len(payloads)

    def test_execute_results_link_to_correct_payloads(self):
        module = PromptInjectionModule()
        payloads = module.generate_payloads({})
        agent = MockAgent()
        results = module.execute(agent)
        result_payload_ids = {r.payload.id for r in results}
        payload_ids = {p.id for p in payloads}
        assert result_payload_ids == payload_ids

    def test_metadata_after_generate(self):
        module = PromptInjectionModule()
        module.generate_payloads({})
        meta = module.get_metadata()
        assert meta["name"] == "llm01_prompt_inject"
        assert meta["payload_count"] == 5
