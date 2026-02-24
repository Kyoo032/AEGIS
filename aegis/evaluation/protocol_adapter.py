"""Adapter from protocol scorers to the existing Scorer interface."""
from __future__ import annotations

from aegis.interfaces.scorer import Scorer
from aegis.interfaces.scorer_protocol import ScorerProtocol
from aegis.models import AttackResult, EvaluationResult


class ProtocolScorerAdapter(Scorer):
    """Wraps a ScorerProtocol to interoperate with EvaluationPipeline."""

    def __init__(self, scorer: ScorerProtocol) -> None:
        self._scorer = scorer
        self.name = scorer.name

    def evaluate(self, result: AttackResult) -> EvaluationResult:
        prompt = _extract_prompt_text(result)
        scored = self._scorer.score(prompt=prompt, response=result.response.final_output)
        confidence = max(0.0, min(1.0, float(scored.confidence)))
        return EvaluationResult(
            attack_result=result,
            success=bool(scored.success),
            confidence=confidence,
            scoring_method=scored.scoring_method,
            explanation=scored.explanation,
            indicators=list(scored.indicators),
            defense_bypassed=bool(scored.success) if result.response.defense_active else None,
            owasp_id=result.payload.owasp_id,
            atlas_technique=result.payload.atlas_technique,
        )


def _extract_prompt_text(result: AttackResult) -> str:
    """Best-effort extraction of user prompt text from payload messages."""
    parts: list[str] = []
    for msg in result.payload.messages:
        role = str(msg.get("role", "")).strip()
        content = str(msg.get("content", "")).strip()
        if not content:
            continue
        if role.lower() == "user":
            parts.append(content)
    if parts:
        return "\n".join(parts)
    return "\n".join(str(msg.get("content", "")) for msg in result.payload.messages).strip()
