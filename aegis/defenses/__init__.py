"""Defense modules sub-package."""
from __future__ import annotations

from typing import Any

from aegis.lazy_loading import load_symbol

_DEFENSE_EXPORTS: dict[str, tuple[str, str]] = {
    "InputValidatorDefense": ("aegis.defenses.input_validator", "InputValidatorDefense"),
    "MCPIntegrityDefense": ("aegis.defenses.mcp_integrity", "MCPIntegrityDefense"),
    "OutputFilterDefense": ("aegis.defenses.output_filter", "OutputFilterDefense"),
    "PermissionEnforcerDefense": (
        "aegis.defenses.permission_enforcer",
        "PermissionEnforcerDefense",
    ),
    "ToolBoundaryDefense": ("aegis.defenses.tool_boundary", "ToolBoundaryDefense"),
}


def __getattr__(name: str) -> Any:
    try:
        module_path, attr_name = _DEFENSE_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    return load_symbol(module_path, attr_name)


__all__ = sorted(_DEFENSE_EXPORTS)
