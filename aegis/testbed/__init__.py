"""Testbed sub-package — Person A owns this directory."""
from __future__ import annotations

from typing import Any

from aegis.lazy_loading import load_symbol

_TESTBED_EXPORTS: dict[str, tuple[str, str]] = {
    "LLMCallError": ("aegis.testbed.retry", "LLMCallError"),
    "MockAgent": ("aegis.testbed.mock_agent", "MockAgent"),
    "MockResponse": ("aegis.testbed.mock_agent", "MockResponse"),
    "call_with_retry": ("aegis.testbed.retry", "call_with_retry"),
}


def __getattr__(name: str) -> Any:
    try:
        module_path, attr_name = _TESTBED_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    return load_symbol(module_path, attr_name)


__all__ = sorted(_TESTBED_EXPORTS)
