"""Trust/provenance helpers for KB retrieval policy."""
from __future__ import annotations

from typing import Any

_TRUST_WEIGHT: dict[str, float] = {
    "trusted": 1.0,
    "neutral": 0.0,
    "unknown": -0.2,
    "untrusted": -1.0,
}


def trust_level(metadata: dict[str, Any]) -> str:
    level = str(metadata.get("trust_level", "neutral")).strip().lower()
    if level not in _TRUST_WEIGHT:
        return "unknown"
    return level


def trust_weight(metadata: dict[str, Any]) -> float:
    return _TRUST_WEIGHT.get(trust_level(metadata), -0.2)


def is_poisoned(metadata: dict[str, Any]) -> bool:
    return bool(metadata.get("is_poisoned", False))
