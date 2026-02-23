"""Retry utilities for LLM/provider calls."""
from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from typing import TypeVar
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class LLMCallError(RuntimeError):
    """Raised when an LLM call fails or exhausts retries."""


def call_with_retry(
    fn: Callable[[], T],
    *,
    max_retries: int,
    timeout_seconds: float,
    base_delay_seconds: float,
    max_delay_seconds: float,
    jitter_seconds: float,
    operation_name: str,
) -> T:
    """Run ``fn`` with retry/backoff for retryable provider failures.

    ``timeout_seconds`` is included for call-site consistency and logging;
    providers should apply request-level timeouts inside ``fn``.
    """
    attempts = max(1, int(max_retries) + 1)
    last_exc: Exception | None = None

    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            retryable = _is_retryable_exception(exc)
            attempt_no = attempt + 1

            if not retryable:
                msg = (
                    f"{operation_name} failed with non-retryable error "
                    f"on attempt {attempt_no}/{attempts}: {exc}"
                )
                raise LLMCallError(msg) from exc

            if attempt_no >= attempts:
                break

            delay = _compute_delay(
                attempt=attempt,
                base_delay_seconds=base_delay_seconds,
                max_delay_seconds=max_delay_seconds,
                jitter_seconds=jitter_seconds,
            )
            logger.warning(
                "%s failed (attempt %d/%d, timeout=%.2fs): %s; retrying in %.2fs",
                operation_name,
                attempt_no,
                attempts,
                timeout_seconds,
                exc,
                delay,
            )
            time.sleep(delay)

    msg = f"{operation_name} failed after {attempts} attempts: {last_exc}"
    raise LLMCallError(msg) from last_exc


def _compute_delay(
    *,
    attempt: int,
    base_delay_seconds: float,
    max_delay_seconds: float,
    jitter_seconds: float,
) -> float:
    exp_delay = max(0.0, float(base_delay_seconds)) * (2 ** max(0, attempt))
    capped = min(max(0.0, float(max_delay_seconds)), exp_delay)
    jitter = random.uniform(0.0, max(0.0, float(jitter_seconds)))
    return capped + jitter


def _is_retryable_exception(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, URLError, ConnectionError)):
        return True

    status_code = _extract_status_code(exc)
    if status_code is None:
        return False

    return status_code == 429 or 500 <= status_code < 600


def _extract_status_code(exc: Exception) -> int | None:
    if isinstance(exc, HTTPError):
        return int(exc.code)

    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        return status_code

    status = getattr(exc, "status", None)
    if isinstance(status, int):
        return status

    response = getattr(exc, "response", None)
    if response is not None:
        resp_code = getattr(response, "status_code", None)
        if isinstance(resp_code, int):
            return resp_code

    return None


__all__ = ["LLMCallError", "call_with_retry"]
