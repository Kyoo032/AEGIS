"""Attack modules registry."""
from aegis.attacks.asi01_goal_hijack import GoalHijackModule
from aegis.attacks.asi02_tool_misuse import ToolMisuseModule
from aegis.attacks.asi04_supply_chain import SupplyChainModule
from aegis.attacks.asi05_code_exec import CodeExecModule
from aegis.attacks.asi06_memory_poison import MemoryPoisonModule
from aegis.attacks.base import BaseAttackModule
from aegis.attacks.llm01_prompt_inject import PromptInjectionModule
from aegis.attacks.llm02_data_disclosure import DataDisclosureModule
from aegis.attacks.mcp06_cmd_injection import CmdInjectionModule

ATTACK_MODULES = {
    "asi01_goal_hijack": GoalHijackModule,
    "asi02_tool_misuse": ToolMisuseModule,
    "asi04_supply_chain": SupplyChainModule,
    "asi05_code_exec": CodeExecModule,
    "asi06_memory_poison": MemoryPoisonModule,
    "mcp06_cmd_injection": CmdInjectionModule,
    "llm01_prompt_inject": PromptInjectionModule,
    "llm02_data_disclosure": DataDisclosureModule,
}


def get_module(name: str):
    """Get an attack module instance by config name."""
    cls = ATTACK_MODULES.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown attack module: {name}. "
            f"Available: {list(ATTACK_MODULES.keys())}"
        )
    return cls()


def get_all_modules():
    """Return instances of all registered attack modules."""
    return [cls() for cls in ATTACK_MODULES.values()]


__all__ = [
    "ATTACK_MODULES",
    "BaseAttackModule",
    "CodeExecModule",
    "CmdInjectionModule",
    "DataDisclosureModule",
    "GoalHijackModule",
    "MemoryPoisonModule",
    "PromptInjectionModule",
    "SupplyChainModule",
    "ToolMisuseModule",
    "get_all_modules",
    "get_module",
]
