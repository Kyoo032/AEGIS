"""Tests for ASI08 cascading failure module."""
from __future__ import annotations

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.asi08_cascading_failure import CascadingFailureModule
from tests.conftest import MockAgent

FULL_TARGET_CONFIG = {
    "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
    "rag_enabled": True,
    "memory_enabled": True,
}


def test_asi08_cascading_failure_registered():
    assert ATTACK_MODULES["asi08_cascading_failure"] is CascadingFailureModule
    assert get_module("asi08_cascading_failure").name == "asi08_cascading_failure"


def test_asi08_cascading_failure_payloads_carry_failure_metadata():
    module = CascadingFailureModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)

    assert payloads
    # Every non-negative payload should declare the failure_signal so the
    # rule detector and judge can locate the propagation evidence.
    for payload in payloads:
        if payload.metadata.get("negative_control"):
            continue
        assert payload.metadata.get("failure_signal"), payload.id


def test_asi08_cascading_failure_covers_required_techniques():
    module = CascadingFailureModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    techniques = {
        payload.metadata.get("technique")
        for payload in payloads
        if not payload.metadata.get("negative_control")
    }

    # Distinct ASI08 failure modes the suite probes.
    expected = {
        "retry_storm",
        "missing_circuit_breaker",
        "failure_propagation",
        "stale_error_bleed",
        "compensating_fanout",
    }
    assert expected.issubset(techniques), techniques


def test_asi08_cascading_failure_module_executes_all_payloads():
    module = CascadingFailureModule()
    payloads = module.generate_payloads(FULL_TARGET_CONFIG)
    agent = MockAgent()

    results = module.execute(agent)

    assert len(results) == len(payloads)
    assert agent.reset_count == len(payloads)
