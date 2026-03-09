"""AEGIS - Agentic Exploit & Guardrail Investigation Suite.

Top-level package. Import shared models and interfaces from here
or from their canonical submodules.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.models import (
        AgentResponse,
        AttackPayload,
        AttackResult,
        EvaluationResult,
        Finding,
        OWASPCategoryResult,
        ScoringMethod,
        SecurityReport,
        Severity,
        ToolCall,
    )

__all__ = [
    "AgentResponse",
    "AttackPayload",
    "AttackResult",
    "EvaluationResult",
    "Finding",
    "OWASPCategoryResult",
    "ScoringMethod",
    "SecurityReport",
    "Severity",
    "ToolCall",
]


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from aegis import models

    return getattr(models, name)


def __dir__() -> list[str]:
    return sorted(list(globals()) + __all__)
