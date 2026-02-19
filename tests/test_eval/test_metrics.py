"""TDD tests for aegis/evaluation/metrics.py — written before implementation."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from aegis.evaluation.metrics import (
    compute_aggregate_stats,
    compute_asr,
    compute_defense_bypass_rate,
    compute_per_category_asr,
)
from aegis.models import (
    AgentResponse,
    AttackPayload,
    AttackResult,
    EvaluationResult,
    ScoringMethod,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_payload(owasp_id: str = "LLM01") -> AttackPayload:
    return AttackPayload(
        id=f"{owasp_id}-TEST-001",
        attack_module="test_module",
        owasp_id=owasp_id,
        category="Test Category",
        messages=[{"role": "user", "content": "test"}],
        expected_behavior="test",
        severity=Severity.LOW,
    )


def _make_response(defense_active: str | None = None) -> AgentResponse:
    return AgentResponse(
        payload_id="TEST-001",
        agent_profile="default",
        messages=[],
        final_output="test output",
        tool_calls=[],
        defense_active=defense_active,
    )


def _make_eval_result(
    owasp_id: str = "LLM01",
    success: bool = True,
    defense_bypassed: bool | None = None,
    defense_active: str | None = None,
) -> EvaluationResult:
    payload = _make_payload(owasp_id)
    response = _make_response(defense_active=defense_active)
    attack_result = AttackResult(
        payload=payload,
        response=response,
        timestamp=datetime.now(UTC),
        run_id="test-run-001",
    )
    return EvaluationResult(
        attack_result=attack_result,
        success=success,
        confidence=0.9 if success else 0.0,
        scoring_method=ScoringMethod.RULE_BASED,
        explanation="test explanation",
        indicators=["indicator-1"] if success else [],
        defense_bypassed=defense_bypassed,
        owasp_id=owasp_id,
    )


# ---------------------------------------------------------------------------
# compute_asr
# ---------------------------------------------------------------------------


class TestComputeAsr:
    def test_empty_list_returns_zero(self):
        assert compute_asr([]) == 0.0

    def test_all_successful_returns_one(self):
        results = [_make_eval_result(success=True) for _ in range(5)]
        assert compute_asr(results) == 1.0

    def test_all_failed_returns_zero(self):
        results = [_make_eval_result(success=False) for _ in range(5)]
        assert compute_asr(results) == 0.0

    def test_mixed_returns_correct_ratio(self):
        results = [
            _make_eval_result(success=True),
            _make_eval_result(success=True),
            _make_eval_result(success=False),
            _make_eval_result(success=False),
        ]
        assert compute_asr(results) == pytest.approx(0.5)

    def test_single_success(self):
        assert compute_asr([_make_eval_result(success=True)]) == 1.0

    def test_single_failure(self):
        assert compute_asr([_make_eval_result(success=False)]) == 0.0

    def test_result_within_bounds(self):
        import random

        random.seed(42)
        results = [_make_eval_result(success=random.choice([True, False])) for _ in range(100)]
        asr = compute_asr(results)
        assert 0.0 <= asr <= 1.0

    def test_does_not_mutate_input(self):
        results = [_make_eval_result(success=True), _make_eval_result(success=False)]
        original_len = len(results)
        compute_asr(results)
        assert len(results) == original_len


# ---------------------------------------------------------------------------
# compute_defense_bypass_rate
# ---------------------------------------------------------------------------


class TestComputeDefenseBypassRate:
    def test_empty_list_returns_zero(self):
        assert compute_defense_bypass_rate([]) == 0.0

    def test_all_none_defense_bypassed_returns_zero(self):
        results = [_make_eval_result(defense_bypassed=None) for _ in range(5)]
        assert compute_defense_bypass_rate(results) == 0.0

    def test_all_bypassed_returns_one(self):
        results = [_make_eval_result(defense_bypassed=True) for _ in range(4)]
        assert compute_defense_bypass_rate(results) == 1.0

    def test_none_bypassed_returns_zero(self):
        results = [_make_eval_result(defense_bypassed=False) for _ in range(4)]
        assert compute_defense_bypass_rate(results) == 0.0

    def test_mixed_bypassed_returns_ratio(self):
        results = [
            _make_eval_result(defense_bypassed=True),
            _make_eval_result(defense_bypassed=True),
            _make_eval_result(defense_bypassed=False),
            _make_eval_result(defense_bypassed=None),  # excluded
        ]
        # 2 tested (bypassed + not bypassed), 2 bypassed of 3 with defense tested
        rate = compute_defense_bypass_rate(results)
        assert rate == pytest.approx(2 / 3)

    def test_only_counts_non_none_defense_bypassed(self):
        baseline_results = [_make_eval_result(defense_bypassed=None) for _ in range(5)]
        defended_results = [
            _make_eval_result(defense_bypassed=True),
            _make_eval_result(defense_bypassed=False),
        ]
        all_results = baseline_results + defended_results
        rate = compute_defense_bypass_rate(all_results)
        assert rate == pytest.approx(0.5)

    def test_result_within_bounds(self):
        results = [
            _make_eval_result(defense_bypassed=True),
            _make_eval_result(defense_bypassed=False),
        ]
        rate = compute_defense_bypass_rate(results)
        assert 0.0 <= rate <= 1.0


# ---------------------------------------------------------------------------
# compute_per_category_asr
# ---------------------------------------------------------------------------


class TestComputePerCategoryAsr:
    def test_empty_list_returns_empty_dict(self):
        assert compute_per_category_asr([]) == {}

    def test_single_category_all_success(self):
        results = [_make_eval_result(owasp_id="LLM01", success=True) for _ in range(3)]
        per_cat = compute_per_category_asr(results)
        assert "LLM01" in per_cat
        assert per_cat["LLM01"] == 1.0

    def test_single_category_all_fail(self):
        results = [_make_eval_result(owasp_id="ASI01", success=False) for _ in range(3)]
        per_cat = compute_per_category_asr(results)
        assert per_cat["ASI01"] == 0.0

    def test_multiple_categories(self):
        results = [
            _make_eval_result(owasp_id="LLM01", success=True),
            _make_eval_result(owasp_id="LLM01", success=False),
            _make_eval_result(owasp_id="ASI01", success=True),
            _make_eval_result(owasp_id="ASI01", success=True),
            _make_eval_result(owasp_id="MCP06", success=False),
        ]
        per_cat = compute_per_category_asr(results)
        assert set(per_cat.keys()) == {"LLM01", "ASI01", "MCP06"}
        assert per_cat["LLM01"] == pytest.approx(0.5)
        assert per_cat["ASI01"] == pytest.approx(1.0)
        assert per_cat["MCP06"] == pytest.approx(0.0)

    def test_values_within_bounds(self):
        results = [
            _make_eval_result(owasp_id="LLM01", success=True),
            _make_eval_result(owasp_id="ASI02", success=False),
        ]
        per_cat = compute_per_category_asr(results)
        for val in per_cat.values():
            assert 0.0 <= val <= 1.0

    def test_returns_dict_str_float(self):
        results = [_make_eval_result(owasp_id="LLM01", success=True)]
        per_cat = compute_per_category_asr(results)
        assert isinstance(per_cat, dict)
        for k, v in per_cat.items():
            assert isinstance(k, str)
            assert isinstance(v, float)


# ---------------------------------------------------------------------------
# compute_aggregate_stats
# ---------------------------------------------------------------------------


class TestComputeAggregateStats:
    def test_empty_list_returns_zero_stats(self):
        stats = compute_aggregate_stats([])
        assert stats["total"] == 0
        assert stats["successful"] == 0
        assert stats["asr"] == 0.0
        assert stats["categories"] == {}

    def test_required_keys_present(self):
        results = [_make_eval_result(success=True)]
        stats = compute_aggregate_stats(results)
        required_keys = {"total", "successful", "asr", "defense_tested", "bypassed", "bypass_rate", "categories"}
        assert required_keys.issubset(set(stats.keys()))

    def test_total_correct(self):
        results = [_make_eval_result() for _ in range(7)]
        assert compute_aggregate_stats(results)["total"] == 7

    def test_successful_correct(self):
        results = [
            _make_eval_result(success=True),
            _make_eval_result(success=True),
            _make_eval_result(success=False),
        ]
        assert compute_aggregate_stats(results)["successful"] == 2

    def test_asr_correct(self):
        results = [
            _make_eval_result(success=True),
            _make_eval_result(success=False),
        ]
        assert compute_aggregate_stats(results)["asr"] == pytest.approx(0.5)

    def test_defense_stats_with_bypassed_results(self):
        results = [
            _make_eval_result(defense_bypassed=True),
            _make_eval_result(defense_bypassed=True),
            _make_eval_result(defense_bypassed=False),
            _make_eval_result(defense_bypassed=None),
        ]
        stats = compute_aggregate_stats(results)
        assert stats["defense_tested"] == 3
        assert stats["bypassed"] == 2
        assert stats["bypass_rate"] == pytest.approx(2 / 3)

    def test_categories_match_per_category_asr(self):
        results = [
            _make_eval_result(owasp_id="LLM01", success=True),
            _make_eval_result(owasp_id="ASI01", success=False),
        ]
        stats = compute_aggregate_stats(results)
        assert "LLM01" in stats["categories"]
        assert "ASI01" in stats["categories"]

    def test_does_not_mutate_input(self):
        results = [_make_eval_result(success=True), _make_eval_result(success=False)]
        original_len = len(results)
        compute_aggregate_stats(results)
        assert len(results) == original_len
