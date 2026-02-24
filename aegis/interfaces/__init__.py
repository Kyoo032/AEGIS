"""Abstract base interfaces for all AEGIS cross-track contracts."""
from aegis.interfaces.agent import AgentInterface
from aegis.interfaces.attack import AttackModule
from aegis.interfaces.defense import Defense
from aegis.interfaces.scorer import Scorer
from aegis.interfaces.scorer_protocol import ScorerProtocol

__all__ = ["AgentInterface", "AttackModule", "Defense", "Scorer", "ScorerProtocol"]
