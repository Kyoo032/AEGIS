"""Tests for aegis/evaluation/protocol_adapter.py."""
from __future__ import annotations

from datetime import UTC, datetime

from aegis.evaluation.protocol_adapter import ProtocolScorerAdapter, _extract_prompt_text
from aegis.interfaces.scorer_protocol import ScorerProtocol, ScorerResult
from aegis.models import (
    AgentResponse,
    AttackPayload,
    AttackResult,
    EvaluationResult,
    ScoringMethod,
    Severity,
)


class FakeProtocolScorer(ScorerProtocol):
    name = "fake_scorer"

    def score(self, *, prompt: str, response: str) -> ScorerResult:
        return ScorerResult(
            success=True,
            confidence=0.9,
            scoring_method=ScoringMethod.RULE_BASED,
            explanation="test",
            indicators=["indicator1"],
        )


def _make_result(messages=None) -> AttackResult:
    msgs = messages or [{"role": "user", "content": "hello"}]
    payload = AttackPayload(
        id="TEST-001",
        attack_module="test_module",
        owasp_id="LLM01",
        atlas_technique="AML.T0051",
        category="Test",
        messages=msgs,
        expected_behavior="test",
        severity=Severity.HIGH,
    )
    response = AgentResponse(
        payload_id="TEST-001",
        agent_profile="default",
        messages=[
            {"role": "user", "content": msgs[0]["content"]},
            {"role": "assistant", "content": "I will comply."},
        ],
        final_output="I will comply.",
        tool_calls=[],
    )
    return AttackResult(
        payload=payload,
        response=response,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        run_id="test-run",
    )


def test_adapter_evaluate_returns_evaluation_result():
    scorer = FakeProtocolScorer()
    adapter = ProtocolScorerAdapter(scorer)
    assert adapter.name == "fake_scorer"

    result = adapter.evaluate(_make_result())
    assert isinstance(result, EvaluationResult)
    assert result.success is True
    assert result.confidence == 0.9
    assert result.owasp_id == "LLM01"
    assert "indicator1" in result.indicators


def test_adapter_clamps_confidence():
    class OverScorer(ScorerProtocol):
        name = "over"

        def score(self, *, prompt: str, response: str) -> ScorerResult:
            return ScorerResult(
                success=False,
                confidence=1.5,
                scoring_method=ScoringMethod.RULE_BASED,
                explanation="too high",
                indicators=[],
            )

    adapter = ProtocolScorerAdapter(OverScorer())
    result = adapter.evaluate(_make_result())
    assert result.confidence == 1.0


def test_extract_prompt_text_user_messages():
    ar = _make_result([
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "second"},
    ])
    text = _extract_prompt_text(ar)
    assert text == "first\nsecond"


def test_extract_prompt_text_no_user_role():
    ar = _make_result([{"role": "system", "content": "only system"}])
    text = _extract_prompt_text(ar)
    assert "only system" in text


def test_adapter_defense_bypassed_set_when_defense_active():
    class PassScorer(ScorerProtocol):
        name = "pass"

        def score(self, *, prompt: str, response: str) -> ScorerResult:
            return ScorerResult(
                success=True,
                confidence=0.8,
                scoring_method=ScoringMethod.RULE_BASED,
                explanation="bypassed",
                indicators=[],
            )

    ar = _make_result()
    ar.response.defense_active = "input_validator"
    adapter = ProtocolScorerAdapter(PassScorer())
    result = adapter.evaluate(ar)
    assert result.defense_bypassed is True
