"""Evidence persistence helpers."""
from __future__ import annotations

from typing import Any

from aegis.lazy_loading import load_symbol

_EVIDENCE_EXPORTS: dict[str, tuple[str, str]] = {
    "EvidenceTraceStore": ("aegis.evidence.store", "EvidenceTraceStore"),
}


def __getattr__(name: str) -> Any:
    try:
        module_path, attr_name = _EVIDENCE_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    return load_symbol(module_path, attr_name)


__all__ = sorted(_EVIDENCE_EXPORTS)
