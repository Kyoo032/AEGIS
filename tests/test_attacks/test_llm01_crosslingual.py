"""Tests for the LLM01 cross-lingual prompt injection module."""
from __future__ import annotations

from aegis.attacks import ATTACK_MODULES, get_module
from aegis.attacks.llm01_crosslingual import CrossLingualPromptInjectionModule
from tests.conftest import MockAgent


def test_llm01_crosslingual_registered():
    assert ATTACK_MODULES["llm01_crosslingual"] is CrossLingualPromptInjectionModule
    assert get_module("llm01_crosslingual").name == "llm01_crosslingual"


def test_llm01_crosslingual_loads_reviewable_payload_metadata():
    module = CrossLingualPromptInjectionModule()
    payloads = module.generate_payloads({})

    assert payloads
    assert all(payload.attack_module == "llm01_crosslingual" for payload in payloads)
    assert all(payload.metadata.get("language") for payload in payloads)
    assert all(payload.metadata.get("naturalness_reviewed") is True for payload in payloads)
    assert all(payload.metadata.get("native_reviewer") is True for payload in payloads)
    assert all(payload.metadata.get("naturalness_label") == "natural" for payload in payloads)
    assert all(payload.metadata.get("native_review_date") == "2026-04-20" for payload in payloads)


def test_llm01_crosslingual_execution_resets_per_payload():
    module = CrossLingualPromptInjectionModule()
    payloads = module.generate_payloads({})
    agent = MockAgent()

    results = module.execute(agent)

    assert len(results) == len(payloads)
    assert agent.reset_count == len(payloads)
