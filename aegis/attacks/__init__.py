"""Attack modules registry."""
from __future__ import annotations

from typing import Any

from aegis.lazy_loading import LazyClassRegistry, load_symbol

_ATTACK_EXPORTS: dict[str, tuple[str, str]] = {
    "BaseAttackModule": ("aegis.attacks.base", "BaseAttackModule"),
    "CodeExecModule": ("aegis.attacks.asi05_code_exec", "CodeExecModule"),
    "CmdInjectionModule": ("aegis.attacks.mcp06_cmd_injection", "CmdInjectionModule"),
    "CrossLingualPromptInjectionModule": (
        "aegis.attacks.llm01_crosslingual",
        "CrossLingualPromptInjectionModule",
    ),
    "DataDisclosureModule": ("aegis.attacks.llm02_data_disclosure", "DataDisclosureModule"),
    "DynamicCloakModule": ("aegis.attacks.asi_dynamic_cloak", "DynamicCloakModule"),
    "GoalHijackModule": ("aegis.attacks.asi01_goal_hijack", "GoalHijackModule"),
    "HITLApprovalModule": ("aegis.attacks.asi_hitl", "HITLApprovalModule"),
    "HumanTrustDeceptionModule": (
        "aegis.attacks.asi09_human_trust",
        "HumanTrustDeceptionModule",
    ),
    "IdentityPrivilegeModule": (
        "aegis.attacks.asi03_identity_privilege",
        "IdentityPrivilegeModule",
    ),
    "InterAgentTrustModule": ("aegis.attacks.asi07_inter_agent", "InterAgentTrustModule"),
    "MemoryPoisonModule": ("aegis.attacks.asi06_memory_poison", "MemoryPoisonModule"),
    "PromptInjectionModule": ("aegis.attacks.llm01_prompt_inject", "PromptInjectionModule"),
    "SemanticManipulationModule": (
        "aegis.attacks.asi_semantic_manip",
        "SemanticManipulationModule",
    ),
    "SupplyChainModule": ("aegis.attacks.asi04_supply_chain", "SupplyChainModule"),
    "ToolMisuseModule": ("aegis.attacks.asi02_tool_misuse", "ToolMisuseModule"),
}

_ATTACK_MODULE_PATHS: dict[str, tuple[str, str]] = {
    "asi01_goal_hijack": ("aegis.attacks.asi01_goal_hijack", "GoalHijackModule"),
    "asi02_tool_misuse": ("aegis.attacks.asi02_tool_misuse", "ToolMisuseModule"),
    "asi03_identity_privilege": (
        "aegis.attacks.asi03_identity_privilege",
        "IdentityPrivilegeModule",
    ),
    "asi04_supply_chain": ("aegis.attacks.asi04_supply_chain", "SupplyChainModule"),
    "asi05_code_exec": ("aegis.attacks.asi05_code_exec", "CodeExecModule"),
    "asi06_memory_poison": ("aegis.attacks.asi06_memory_poison", "MemoryPoisonModule"),
    "asi07_inter_agent": ("aegis.attacks.asi07_inter_agent", "InterAgentTrustModule"),
    "asi09_human_trust": (
        "aegis.attacks.asi09_human_trust",
        "HumanTrustDeceptionModule",
    ),
    "asi_dynamic_cloak": ("aegis.attacks.asi_dynamic_cloak", "DynamicCloakModule"),
    "asi_hitl": ("aegis.attacks.asi_hitl", "HITLApprovalModule"),
    "asi_semantic_manip": (
        "aegis.attacks.asi_semantic_manip",
        "SemanticManipulationModule",
    ),
    "mcp06_cmd_injection": ("aegis.attacks.mcp06_cmd_injection", "CmdInjectionModule"),
    "llm01_crosslingual": (
        "aegis.attacks.llm01_crosslingual",
        "CrossLingualPromptInjectionModule",
    ),
    "llm01_prompt_inject": ("aegis.attacks.llm01_prompt_inject", "PromptInjectionModule"),
    "llm02_data_disclosure": (
        "aegis.attacks.llm02_data_disclosure",
        "DataDisclosureModule",
    ),
}

ATTACK_MODULES = LazyClassRegistry(_ATTACK_MODULE_PATHS)


def get_module(name: str):
    """Get an attack module instance by config name."""
    try:
        cls = ATTACK_MODULES[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown attack module: {name}. "
            f"Available: {list(ATTACK_MODULES.keys())}"
        ) from exc
    return cls()


def get_all_modules():
    """Return instances of all registered attack modules."""
    return [ATTACK_MODULES[name]() for name in ATTACK_MODULES]


def __getattr__(name: str) -> Any:
    try:
        module_path, attr_name = _ATTACK_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    return load_symbol(module_path, attr_name)


__all__ = ["ATTACK_MODULES", *sorted(_ATTACK_EXPORTS), "get_all_modules", "get_module"]
