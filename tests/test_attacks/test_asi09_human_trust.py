"""Tests for ASI09 human trust deception module."""
from __future__ import annotations

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi09_human_trust import HumanTrustDeceptionModule
from tests.conftest import MockAgent


def test_asi09_human_trust_registered():
    assert ATTACK_MODULES["asi09_human_trust"] is HumanTrustDeceptionModule
    assert get_module("asi09_human_trust").name == "asi09_human_trust"


def test_asi09_human_trust_loads_trust_metadata():
    module = HumanTrustDeceptionModule()
    payloads = module.generate_payloads({})

    assert payloads
    assert all(payload.attack_module == "asi09_human_trust" for payload in payloads)
    assert all(payload.metadata.get("trust_signal") for payload in payloads)
    assert all(payload.metadata.get("expected_signal") for payload in payloads)


def test_asi09_human_trust_execution_resets_per_payload():
    module = HumanTrustDeceptionModule()
    payloads = module.generate_payloads({})
    agent = MockAgent(final_output="This is completely safe and verified.")

    results = module.execute(agent)

    assert len(results) == len(payloads)
    assert agent.reset_count == len(payloads)
