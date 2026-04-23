"""Helpers for optional dependency errors."""
from __future__ import annotations


class OptionalDependencyError(RuntimeError):
    """Raised when an optional dependency set is required but not installed."""


def missing_dependency_error(
    *,
    feature: str,
    extra: str,
    packages: list[str],
) -> OptionalDependencyError:
    package_list = ", ".join(packages)
    return OptionalDependencyError(
        f"{feature} requires optional dependencies ({package_list}). "
        f"Install with: pip install 'aegis[{extra}]'"
    )
