"""Protocol-style scorer interface for dependency-injected scoring backends."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from aegis.models import ScoringMethod


@dataclass(slots=True)
class ScorerResult:
    """Normalized output returned by protocol scorers."""

    success: bool
    confidence: float
    explanation: str
    indicators: list[str] = field(default_factory=list)
    scoring_method: ScoringMethod = ScoringMethod.SEMANTIC


class ScorerProtocol(Protocol):
    """Protocol for swappable scorers independent of AttackResult shape."""

    name: str

    def score(self, prompt: str, response: str) -> ScorerResult:
        """Score a prompt/response pair and return a normalized result."""
        ...
