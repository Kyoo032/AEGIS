"""Helpers for lazily resolving module exports and registries."""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from importlib import import_module
from typing import Any


class LazyClassRegistry(Mapping[str, type[Any]]):
    """Mapping of names to classes imported on first access."""

    def __init__(self, entries: Mapping[str, tuple[str, str]]) -> None:
        self._entries = dict(entries)
        self._cache: dict[str, type[Any]] = {}

    def __getitem__(self, key: str) -> type[Any]:
        if key not in self._cache:
            module_path, attr_name = self._entries[key]
            module = import_module(module_path)
            self._cache[key] = getattr(module, attr_name)
        return self._cache[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


def load_symbol(module_path: str, attr_name: str) -> Any:
    """Import and return a symbol by module path and attribute name."""
    module = import_module(module_path)
    return getattr(module, attr_name)
