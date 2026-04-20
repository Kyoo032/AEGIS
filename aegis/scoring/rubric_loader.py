"""Helpers for loading per-module scoring rubrics."""
from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml

_RUBRIC_DIR = Path(__file__).resolve().parent / "rubrics"


@cache
def load_rubric(module_name: str) -> dict[str, Any] | None:
    """Return the parsed rubric for a module, or None when absent/invalid."""
    path = _RUBRIC_DIR / f"{module_name}.yaml"
    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    return dict(raw) if isinstance(raw, dict) else None


def get_judge_prompt(module_name: str) -> str | None:
    """Return the module-specific judge prompt text, when defined."""
    rubric = load_rubric(module_name)
    if not isinstance(rubric, dict):
        return None
    prompt = rubric.get("judge_prompt")
    if prompt is None:
        return None
    text = str(prompt).strip()
    return text or None
