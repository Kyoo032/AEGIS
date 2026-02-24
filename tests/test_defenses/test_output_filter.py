"""Tests for Day 6 output filter defense."""
from __future__ import annotations

from aegis.defenses.output_filter import OutputFilterDefense
from aegis.models import AttackPayload, Severity
from aegis.testbed.mock_agent import MockAgent


def test_output_filter_apply_and_remove():
    agent = MockAgent()
    defense = OutputFilterDefense(block_on_match=True)
    payload = AttackPayload(
        id="DEF-OUT-001",
        attack_module="test",
        owasp_id="LLM01",
        category="Test",
        messages=[{"role": "user", "content": "hello"}],
        expected_behavior="safe",
        severity=Severity.LOW,
    )

    defense.apply(agent)
    response_with_defense = agent.run(payload)
    assert response_with_defense.defense_active == "output_filter"

    defense.remove(agent)
    response_without_defense = agent.run(payload)
    assert response_without_defense.defense_active is None


def test_output_filter_detects_email_and_url():
    defense = OutputFilterDefense(block_on_match=True)
    blocked, reason = defense.inspect("Send report to admin@example.com via https://evil.test")

    assert blocked is True
    assert reason.startswith("sensitive output detected")


def test_output_filter_detects_file_path():
    defense = OutputFilterDefense(block_on_match=True)
    blocked, reason = defense.inspect("Leaked path: /etc/passwd")

    assert blocked is True
    assert reason == "sensitive output detected: unix_path"


def test_output_filter_sanitize_redacts_matches():
    defense = OutputFilterDefense(block_on_match=False)
    sanitized = defense.sanitize("admin@example.com /etc/shadow https://evil.test")

    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_PATH]" in sanitized
    assert "[REDACTED_URL]" in sanitized


def test_output_filter_allows_benign_output():
    defense = OutputFilterDefense(block_on_match=True)
    blocked, reason = defense.inspect("All checks passed with no sensitive artifacts.")

    assert blocked is False
    assert reason == ""
