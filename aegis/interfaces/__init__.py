"""Abstract base interfaces for all AEGIS cross-track contracts."""
from __future__ import annotations

from typing import Any

from aegis.lazy_loading import load_symbol

_INTERFACE_EXPORTS: dict[str, tuple[str, str]] = {
    "AgentInterface": ("aegis.interfaces.agent", "AgentInterface"),
    "AttackModule": ("aegis.interfaces.attack", "AttackModule"),
    "Defense": ("aegis.interfaces.defense", "Defense"),
    "Scorer": ("aegis.interfaces.scorer", "Scorer"),
    "ScorerProtocol": ("aegis.interfaces.scorer_protocol", "ScorerProtocol"),
}


def __getattr__(name: str) -> Any:
    try:
        module_path, attr_name = _INTERFACE_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    return load_symbol(module_path, attr_name)


__all__ = sorted(_INTERFACE_EXPORTS)
