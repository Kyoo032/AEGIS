"""Tests for lazy orchestrator initialization."""
from __future__ import annotations

from aegis.orchestrator import AEGISOrchestrator


def test_orchestrator_init_defers_agent_and_attack_loading():
    orchestrator = AEGISOrchestrator()

    assert orchestrator._agent is None
    assert orchestrator.attacks is None
