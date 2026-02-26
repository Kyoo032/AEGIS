"""Retrieval reranking and trust-enforcement logic."""
from __future__ import annotations

from typing import Any

from aegis.testbed.kb.models import KBDocument, KBHit
from aegis.testbed.kb.policy import is_poisoned, trust_level, trust_weight


def rerank(
    candidates: list[tuple[float, KBDocument]],
    *,
    mode: str,
    trust_enforcement: str,
    limit: int,
) -> tuple[list[KBHit], list[KBHit]]:
    """Rerank lexical candidates and split into included/blocked hits."""
    scored_hits: list[KBHit] = []

    for base_score, document in candidates:
        meta = dict(document.metadata)
        adjusted = _adjust_score(base_score, meta, mode)

        blocked = False
        reason: str | None = None
        level = trust_level(meta)
        poisoned = is_poisoned(meta)
        if trust_enforcement == "strict" and (poisoned or level in {"untrusted", "unknown"}):
            blocked = True
            reason = "strict trust enforcement"

        hit = KBHit(
            doc_id=document.doc_id,
            score=adjusted,
            snippet=_snippet(document.content),
            content=document.content,
            metadata=meta,
            blocked=blocked,
            block_reason=reason,
        )
        scored_hits.append(hit)

    scored_hits.sort(key=lambda hit: (hit.score, hit.doc_id), reverse=True)

    included: list[KBHit] = []
    blocked_hits: list[KBHit] = []
    for hit in scored_hits:
        if hit.blocked:
            blocked_hits.append(hit)
            continue
        if len(included) < limit:
            included.append(hit)

    return included, blocked_hits


def _adjust_score(base_score: float, metadata: dict[str, Any], mode: str) -> float:
    trust = trust_weight(metadata)
    poisoned = is_poisoned(metadata)

    if mode == "attack_sim":
        poison_bonus = 0.25 if poisoned else 0.0
        return base_score + poison_bonus + (0.05 * trust)
    if mode == "hardened":
        poison_penalty = -0.35 if poisoned else 0.0
        return base_score + poison_penalty + (0.3 * trust)

    # baseline
    poison_penalty = -0.1 if poisoned else 0.0
    return base_score + poison_penalty + (0.15 * trust)


def _snippet(content: str, max_chars: int = 180) -> str:
    stripped = " ".join(content.split())
    if len(stripped) <= max_chars:
        return stripped
    return stripped[: max_chars - 3] + "..."
