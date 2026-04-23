"""Evaluation sub-package — scoring and detection for attack results."""
from __future__ import annotations

from typing import Any

from aegis.lazy_loading import load_symbol

_EVALUATION_EXPORTS: dict[str, tuple[str, str]] = {
    "EvaluationPipeline": ("aegis.evaluation.pipeline", "EvaluationPipeline"),
    "RuleBasedScorer": ("aegis.evaluation.scorer", "RuleBasedScorer"),
    "RuleDetector": ("aegis.evaluation.rule_detector", "RuleDetector"),
}


def __getattr__(name: str) -> Any:
    try:
        module_path, attr_name = _EVALUATION_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    return load_symbol(module_path, attr_name)


__all__ = sorted(_EVALUATION_EXPORTS)
