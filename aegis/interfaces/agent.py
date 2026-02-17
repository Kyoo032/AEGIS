"""AgentInterface — Backend Lead implements. Security Lead calls."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from aegis.models import AgentResponse, AttackPayload


class AgentInterface(ABC):
    """Abstract base class for all AEGIS victim agent implementations."""

    @abstractmethod
    def run(self, payload: AttackPayload) -> AgentResponse:
        """Send an attack payload to the agent, return structured response."""
        ...

    @abstractmethod
    def reset(self) -> None:
        """Reset agent state (memory, context) between test runs."""
        ...

    @abstractmethod
    def get_config(self) -> dict[str, Any]:
        """Return current agent configuration (model, tools, profile)."""
        ...

    @abstractmethod
    def enable_defense(self, defense_name: str, config: dict[str, Any]) -> None:
        """Activate a defense module on the agent."""
        ...

    @abstractmethod
    def disable_defense(self, defense_name: str) -> None:
        """Deactivate a defense module."""
        ...

    @abstractmethod
    def inject_context(self, context: str, method: str) -> None:
        """Inject content into RAG store or memory.

        Args:
            context: The text content to inject.
            method: One of 'rag' | 'memory' | 'tool_output'
        """
        ...
