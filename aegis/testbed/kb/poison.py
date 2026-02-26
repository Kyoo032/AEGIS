"""Poisoning helpers for controlled KB attack simulation."""
from __future__ import annotations

from typing import Any


def poison_metadata(
    metadata: dict[str, Any] | None,
    *,
    attack_family: str | None = None,
    injection_method: str | None = None,
) -> dict[str, Any]:
    """Return metadata annotated as poisoned/untrusted."""
    out = dict(metadata or {})
    out["is_poisoned"] = True
    out.setdefault("trust_level", "untrusted")
    if attack_family:
        out["attack_family"] = attack_family
    if injection_method:
        out["injection_method"] = injection_method
    return out
