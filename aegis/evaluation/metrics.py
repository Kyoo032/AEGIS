"""Attack metric computation functions for AEGIS evaluation pipeline.

All functions are pure — no side effects, no mutation of input lists.
Empty inputs return 0.0 or empty structures without raising.
"""
from __future__ import annotations

from typing import Any

from aegis.models import EvaluationResult


def compute_asr(results: list[EvaluationResult]) -> float:
    """Compute the Attack Success Rate.

    Returns:
        Fraction of results where ``success`` is True, in [0.0, 1.0].
        Returns 0.0 for an empty list.
    """
    if not results:
        return 0.0
    successful = sum(1 for r in results if r.success)
    return successful / len(results)


def compute_defense_bypass_rate(results: list[EvaluationResult]) -> float:
    """Compute the rate at which defenses were bypassed.

    Only considers results where ``defense_bypassed`` is not None
    (i.e., a defense was active during that run).

    Returns:
        Fraction of defense-tested results where the attack bypassed the
        defense, in [0.0, 1.0].  Returns 0.0 if no defense-tested results.
    """
    tested = [r for r in results if r.defense_bypassed is not None]
    if not tested:
        return 0.0
    bypassed = sum(1 for r in tested if r.defense_bypassed is True)
    return bypassed / len(tested)


def compute_per_category_asr(results: list[EvaluationResult]) -> dict[str, float]:
    """Compute the Attack Success Rate per OWASP category.

    Returns:
        Mapping of ``owasp_id`` → ASR float in [0.0, 1.0].
        Returns an empty dict for an empty input list.
    """
    if not results:
        return {}

    totals: dict[str, int] = {}
    successes: dict[str, int] = {}

    for r in results:
        owasp_id = r.owasp_id
        totals[owasp_id] = totals.get(owasp_id, 0) + 1
        if r.success:
            successes[owasp_id] = successes.get(owasp_id, 0) + 1

    return {
        owasp_id: successes.get(owasp_id, 0) / total
        for owasp_id, total in totals.items()
    }


def compute_aggregate_stats(results: list[EvaluationResult]) -> dict[str, Any]:
    """Compute aggregated statistics across all evaluation results.

    Returns:
        Dict with keys:
        - ``total``: int — total number of results
        - ``successful``: int — count of successful attacks
        - ``asr``: float — overall attack success rate
        - ``defense_tested``: int — results with a defense active
        - ``bypassed``: int — results that bypassed a defense
        - ``bypass_rate``: float — fraction of defense-tested that were bypassed
        - ``categories``: dict[str, float] — per-OWASP ASR breakdown
    """
    total = len(results)
    successful = sum(1 for r in results if r.success)
    asr = successful / total if total else 0.0

    tested = [r for r in results if r.defense_bypassed is not None]
    defense_tested = len(tested)
    bypassed = sum(1 for r in tested if r.defense_bypassed is True)
    bypass_rate = bypassed / defense_tested if defense_tested else 0.0

    return {
        "total": total,
        "successful": successful,
        "asr": asr,
        "defense_tested": defense_tested,
        "bypassed": bypassed,
        "bypass_rate": bypass_rate,
        "categories": compute_per_category_asr(results),
    }
