"""Unit tests for all configured attack modules."""
from __future__ import annotations

import pytest

from aegis.attacks import ATTACK_MODULES, get_all_modules, get_module
from aegis.attacks.asi01_goal_hijack import GoalHijackModule
from aegis.attacks.asi02_tool_misuse import ToolMisuseModule
from aegis.attacks.asi03_identity_privilege import IdentityPrivilegeModule
from aegis.attacks.asi04_supply_chain import SupplyChainModule
from aegis.attacks.asi05_code_exec import CodeExecModule
from aegis.attacks.asi06_memory_poison import MemoryPoisonModule
from aegis.attacks.asi07_inter_agent import InterAgentTrustModule
from aegis.attacks.asi09_human_trust import HumanTrustDeceptionModule
from aegis.attacks.asi_dynamic_cloak import DynamicCloakModule
from aegis.attacks.asi_hitl import HITLApprovalModule
from aegis.attacks.asi_semantic_manip import SemanticManipulationModule
from aegis.attacks.llm01_crosslingual import CrossLingualPromptInjectionModule
from aegis.attacks.llm01_prompt_inject import PromptInjectionModule
from aegis.attacks.llm02_data_disclosure import DataDisclosureModule
from aegis.attacks.mcp06_cmd_injection import CmdInjectionModule
from aegis.models import AttackPayload

FULL_TARGET_CONFIG = {
    "model": "qwen3:4b",
    "model_provider": "offline",
    "agent_profile": "default",
    "mcp_servers": ["filesystem", "http", "email", "code_exec", "database"],
    "rag_enabled": True,
    "memory_enabled": True,
}

MINIMAL_TARGET_CONFIG = {
    "model": "qwen3:4b",
    "model_provider": "offline",
    "agent_profile": "minimal",
    "mcp_servers": [],
    "rag_enabled": False,
    "memory_enabled": False,
}

ALL_MODULE_CLASSES = [
    GoalHijackModule,
    ToolMisuseModule,
    IdentityPrivilegeModule,
    SupplyChainModule,
    CodeExecModule,
    MemoryPoisonModule,
    InterAgentTrustModule,
    HumanTrustDeceptionModule,
    DynamicCloakModule,
    HITLApprovalModule,
    SemanticManipulationModule,
    CmdInjectionModule,
    CrossLingualPromptInjectionModule,
    PromptInjectionModule,
    DataDisclosureModule,
]

EXPECTED_MODULES = {
    "asi01_goal_hijack": ("ASI01", "AML.T0051"),
    "asi02_tool_misuse": ("ASI02", "AML.T0040"),
    "asi03_identity_privilege": ("ASI03", None),
    "asi04_supply_chain": ("ASI04", "AML.T0010"),
    "asi05_code_exec": ("ASI05", "AML.T0051"),
    "asi06_memory_poison": ("ASI06", "AML.T0020"),
    "asi07_inter_agent": ("ASI07", None),
    "asi09_human_trust": ("ASI09", None),
    "asi_dynamic_cloak": ("ASI-DYNAMIC-CLOAK", None),
    "asi_hitl": ("ASI-HITL", None),
    "asi_semantic_manip": ("ASI-SEMANTIC-MANIP", None),
    "mcp06_cmd_injection": ("MCP06", "AML.T0040"),
    "llm01_crosslingual": ("LLM01", "AML.T0051"),
    "llm01_prompt_inject": ("LLM01", "AML.T0051"),
    "llm02_data_disclosure": ("LLM02", "AML.T0024"),
}

EMPTY_SCAFFOLD_MODULES = set()


class TestModuleRegistry:
    def test_all_modules_registered(self):
        for name in EXPECTED_MODULES:
            assert name in ATTACK_MODULES

    def test_get_module_returns_instance(self):
        for name in EXPECTED_MODULES:
            module = get_module(name)
            assert module.name == name

    def test_get_module_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown attack module"):
            get_module("does_not_exist")

    def test_get_all_modules_count(self):
        modules = get_all_modules()
        assert len(modules) == len(EXPECTED_MODULES)


@pytest.mark.parametrize("module_cls", ALL_MODULE_CLASSES)
class TestModuleInstantiation:
    def test_can_instantiate(self, module_cls):
        module = module_cls()
        assert module is not None

    def test_has_required_attributes(self, module_cls):
        module = module_cls()
        assert module.name
        assert module.owasp_id
        assert module.description
        assert module.category

    def test_owasp_mapping_correct(self, module_cls):
        module = module_cls()
        expected_owasp, expected_atlas = EXPECTED_MODULES[module.name]
        assert module.owasp_id == expected_owasp
        assert module.atlas_technique == expected_atlas

    def test_metadata_complete(self, module_cls):
        module = module_cls()
        meta = module.get_metadata()
        assert "name" in meta
        assert "owasp_id" in meta
        assert "atlas_technique" in meta
        assert "description" in meta


@pytest.mark.parametrize("module_cls", ALL_MODULE_CLASSES)
class TestPayloadGeneration:
    def test_generates_payloads_full_config(self, module_cls):
        module = module_cls()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        if module.name in EMPTY_SCAFFOLD_MODULES:
            assert payloads == []
        else:
            assert len(payloads) > 0

    def test_payloads_are_attack_payload_type(self, module_cls):
        module = module_cls()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        for payload in payloads:
            assert isinstance(payload, AttackPayload)

    def test_payload_ids_unique(self, module_cls):
        module = module_cls()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        payload_ids = [payload.id for payload in payloads]
        assert len(payload_ids) == len(set(payload_ids))

    def test_payload_owasp_id_matches_module(self, module_cls):
        module = module_cls()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        for payload in payloads:
            assert payload.owasp_id == module.owasp_id

    def test_payload_has_messages(self, module_cls):
        module = module_cls()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        for payload in payloads:
            assert payload.messages

    def test_payload_has_expected_behavior(self, module_cls):
        module = module_cls()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        for payload in payloads:
            assert payload.expected_behavior

    def test_payload_severity_valid(self, module_cls):
        module = module_cls()
        payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        valid = {"critical", "high", "medium", "low"}
        for payload in payloads:
            assert payload.severity in valid

    def test_minimal_config_filters_tool_payloads(self, module_cls):
        module = module_cls()
        full_payloads = module.generate_payloads(FULL_TARGET_CONFIG)
        minimal_payloads = module_cls().generate_payloads(MINIMAL_TARGET_CONFIG)
        assert len(minimal_payloads) <= len(full_payloads)
