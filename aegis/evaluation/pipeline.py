"""EvaluationPipeline — runs multiple scorers and resolves disagreements.

When scorers disagree the higher-confidence result wins.
On a tie, rule-based scorer takes precedence.
If a scorer raises, its result is skipped and the others proceed.
"""
from __future__ import annotations

import logging

from aegis.interfaces.scorer import Scorer
from aegis.models import AttackResult, EvaluationResult, ScoringMethod

logger = logging.getLogger(__name__)

# Rule-based scorer name gets priority on ties
_RULE_BASED_NAME = ScoringMethod.RULE_BASED


class EvaluationPipeline:
    """Runs all configured scorers against a list of AttackResult objects.

    Resolution rules (per result):
    1. If only one scorer produces a result, use it.
    2. Among all valid results, pick the one with the highest confidence.
    3. On confidence tie, prefer the rule-based scorer.
    """

    def __init__(self, scorers: list[Scorer], config: dict | None = None) -> None:
        self._scorers = scorers
        self._config = config or {}

    def evaluate(self, results: list[AttackResult]) -> list[EvaluationResult]:
        """Score every AttackResult with all scorers and return resolved results."""
        return [self._resolve(ar) for ar in results]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_one(self, scorer: Scorer, ar: AttackResult) -> EvaluationResult | None:
        """Run a single scorer, returning None if it raises."""
        try:
            return scorer.evaluate(ar)
        except Exception as exc:
            logger.warning("Scorer %r raised on result %r: %s", scorer, ar.payload.id, exc)
            return None

    def _resolve(self, ar: AttackResult) -> EvaluationResult:
        """Pick the best EvaluationResult for a single AttackResult."""
        scored: list[EvaluationResult] = []
        for scorer in self._scorers:
            result = self._score_one(scorer, ar)
            if result is not None:
                scored.append(result)

        if not scored:
            raise RuntimeError(f"All scorers failed for payload {ar.payload.id!r}")

        if len(scored) == 1:
            return scored[0]

        return self._resolve_disagreement(scored, severity=str(ar.payload.severity))

    def _resolve_disagreement(
        self,
        scored: list[EvaluationResult],
        severity: str | None = None,
    ) -> EvaluationResult:
        """Resolve multiple scorer results and log true disagreements."""
        winner = max(scored, key=lambda er: (er.confidence, _tiebreak(er)))
        all_scorers_succeeded = len(scored) == len(self._scorers)
        if all_scorers_succeeded and len({er.success for er in scored}) > 1:
            confidences = [er.confidence for er in scored]
            confidence_spread = max(confidences) - min(confidences)
            review_suffix = " (flagged for review)" if confidence_spread <= 0.1 else ""
            log_level = (
                logging.ERROR
                if (severity or "").lower() in {"critical", "high"}
                else logging.WARNING
            )
            logger.log(
                log_level,
                "DISAGREE: payload=%s winner=%s success=%s confidence=%.2f spread=%.2f%s",
                winner.attack_result.payload.id,
                winner.scoring_method,
                winner.success,
                winner.confidence,
                confidence_spread,
                review_suffix,
            )
        return winner


def _tiebreak(er: EvaluationResult) -> int:
    """Return 1 for rule-based, 0 for everything else (used as sort key)."""
    return 1 if er.scoring_method == _RULE_BASED_NAME else 0
