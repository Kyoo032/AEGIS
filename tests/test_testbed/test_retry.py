"""Tests for aegis/testbed/retry.py."""
from __future__ import annotations

from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from aegis.testbed.retry import (
    LLMCallError,
    _compute_delay,
    _extract_status_code,
    _is_retryable_exception,
    call_with_retry,
)


def test_call_with_retry_returns_on_first_success():
    result = call_with_retry(
        lambda: 42,
        max_retries=3,
        timeout_seconds=5.0,
        base_delay_seconds=0.01,
        max_delay_seconds=0.1,
        jitter_seconds=0.0,
        operation_name="test",
    )
    assert result == 42


def test_call_with_retry_retries_on_timeout():
    calls = {"count": 0}

    def flaky():
        calls["count"] += 1
        if calls["count"] < 3:
            raise TimeoutError("timeout")
        return "ok"

    with patch("aegis.testbed.retry.time.sleep"):
        result = call_with_retry(
            flaky,
            max_retries=3,
            timeout_seconds=5.0,
            base_delay_seconds=0.01,
            max_delay_seconds=0.1,
            jitter_seconds=0.0,
            operation_name="test",
        )
    assert result == "ok"
    assert calls["count"] == 3


def test_call_with_retry_raises_on_non_retryable():
    with pytest.raises(LLMCallError, match="non-retryable"):
        call_with_retry(
            lambda: (_ for _ in ()).throw(ValueError("bad input")),
            max_retries=3,
            timeout_seconds=5.0,
            base_delay_seconds=0.01,
            max_delay_seconds=0.1,
            jitter_seconds=0.0,
            operation_name="test",
        )


def test_call_with_retry_exhausts_retries():
    with patch("aegis.testbed.retry.time.sleep"):
        with pytest.raises(LLMCallError, match="failed after"):
            call_with_retry(
                lambda: (_ for _ in ()).throw(TimeoutError("timeout")),
                max_retries=2,
                timeout_seconds=5.0,
                base_delay_seconds=0.01,
                max_delay_seconds=0.1,
                jitter_seconds=0.0,
                operation_name="test",
            )


def test_compute_delay_exponential_backoff():
    d0 = _compute_delay(attempt=0, base_delay_seconds=1.0, max_delay_seconds=10.0, jitter_seconds=0.0)
    d1 = _compute_delay(attempt=1, base_delay_seconds=1.0, max_delay_seconds=10.0, jitter_seconds=0.0)
    d2 = _compute_delay(attempt=2, base_delay_seconds=1.0, max_delay_seconds=10.0, jitter_seconds=0.0)
    assert d0 == 1.0
    assert d1 == 2.0
    assert d2 == 4.0


def test_compute_delay_caps_at_max():
    d = _compute_delay(attempt=10, base_delay_seconds=1.0, max_delay_seconds=5.0, jitter_seconds=0.0)
    assert d == 5.0


def test_is_retryable_timeout():
    assert _is_retryable_exception(TimeoutError()) is True


def test_is_retryable_connection_error():
    assert _is_retryable_exception(ConnectionError()) is True


def test_is_retryable_url_error():
    assert _is_retryable_exception(URLError("network")) is True


def test_is_not_retryable_value_error():
    assert _is_retryable_exception(ValueError()) is False


def test_is_retryable_429():
    exc = type("Exc", (Exception,), {"status_code": 429})()
    assert _is_retryable_exception(exc) is True


def test_is_retryable_500():
    exc = type("Exc", (Exception,), {"status_code": 500})()
    assert _is_retryable_exception(exc) is True


def test_is_not_retryable_400():
    exc = type("Exc", (Exception,), {"status_code": 400})()
    assert _is_retryable_exception(exc) is False


def test_extract_status_code_http_error():
    exc = HTTPError("http://example.com", 503, "Service Unavailable", {}, None)
    assert _extract_status_code(exc) == 503


def test_extract_status_code_attr():
    exc = type("Exc", (Exception,), {"status_code": 429})()
    assert _extract_status_code(exc) == 429


def test_extract_status_code_status_attr():
    exc = type("Exc", (Exception,), {"status": 502})()
    assert _extract_status_code(exc) == 502


def test_extract_status_code_response_attr():
    resp = type("Resp", (), {"status_code": 504})()
    exc = type("Exc", (Exception,), {"response": resp})()
    assert _extract_status_code(exc) == 504


def test_extract_status_code_none():
    assert _extract_status_code(ValueError("no status")) is None
