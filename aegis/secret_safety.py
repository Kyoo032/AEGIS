"""Helpers for safe handling of sensitive values in diagnostics."""
from __future__ import annotations

import hashlib
from urllib.parse import ParseResult, urlparse


def secret_fingerprint(value: str, *, length: int = 12) -> str:
    """Return a short, non-reversible fingerprint for diagnostics."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:length]}"


def redacted_secret(value: str | None) -> str:
    """Return a safe display value for a secret."""
    if not value:
        return "<unset>"
    return f"<redacted:{secret_fingerprint(value)}>"


def parse_secretless_base_url(
    base_url: str,
    *,
    allowed_schemes: frozenset[str],
    label: str,
) -> ParseResult:
    """Parse and validate a provider base URL without secret-bearing parts."""
    normalized = str(base_url).strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in allowed_schemes or not parsed.netloc:
        if allowed_schemes == frozenset({"https"}):
            raise ValueError(f"{label} base_url must be an HTTPS URL with a host")
        schemes = ", ".join(sorted(allowed_schemes))
        raise ValueError(f"{label} base_url must use {schemes} and include a host")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError(
            f"{label} base_url must not include credentials, params, query strings, or fragments"
        )
    return parsed


__all__ = ["parse_secretless_base_url", "redacted_secret", "secret_fingerprint"]
