"""Scorer — Security Lead implements. Evaluation pipeline calls."""
from abc import ABC, abstractmethod

from aegis.models import AttackResult, EvaluationResult


class Scorer(ABC):
    """Abstract base class for all AEGIS evaluation scorers."""

    name: str

    @abstractmethod
    def evaluate(self, result: AttackResult) -> EvaluationResult:
        """Score a single attack result."""
        ...
