"""Defense — Backend Lead implements. Plugs into AgentInterface."""
from abc import ABC, abstractmethod

from aegis.interfaces.agent import AgentInterface


class Defense(ABC):
    """Abstract base class for all AEGIS defense modules."""

    name: str
    description: str = ""

    @abstractmethod
    def apply(self, agent: AgentInterface) -> None:
        """Install this defense on the agent."""
        ...

    @abstractmethod
    def remove(self, agent: AgentInterface) -> None:
        """Remove this defense from the agent."""
        ...

    @abstractmethod
    def inspect(self, input_data: str | dict) -> tuple[bool, str]:
        """Check if input should be blocked.

        Returns:
            Tuple of (blocked: bool, reason: str).
        """
        ...
