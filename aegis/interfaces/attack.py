"""AttackModule — Security Lead implements. Orchestrator calls."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from aegis.interfaces.agent import AgentInterface
from aegis.models import AttackPayload, AttackResult


class AttackModule(ABC):
    """Abstract base class for all AEGIS attack modules."""

    name: str
    owasp_id: str
    atlas_technique: str | None = None
    description: str = ""
    supports_multi_turn: bool = False
    max_turns: int = 1

    @abstractmethod
    def generate_payloads(self, target_config: dict[str, Any]) -> list[AttackPayload]:
        """Generate attack payloads based on target agent configuration."""
        ...

    @abstractmethod
    def execute(self, agent: AgentInterface) -> list[AttackResult]:
        """Run all payloads against the agent, return results."""
        ...

    def limit_payloads(self, max_count: int) -> None:
        """Optionally trim generated payloads before execution."""
        _ = max_count

    @abstractmethod
    def get_metadata(self) -> dict[str, Any]:
        """Return module metadata for reporting."""
        ...
