"""Small in-memory rate limiter for public dashboard demo scans."""
from __future__ import annotations

import time
from collections import defaultdict, deque

_HOURLY_EVENTS: dict[str, deque[float]] = defaultdict(deque)
_DAILY_EVENTS: dict[str, deque[float]] = defaultdict(deque)


def check_rate_limit(
    client_id: str,
    *,
    hourly_limit: int = 5,
    daily_limit: int = 20,
    now: float | None = None,
) -> tuple[bool, int, str]:
    """Return whether a client may start another scan.

    The limiter is process-local. It is intentionally simple for Streamlit Cloud
    trials and should be replaced with durable storage for a multi-worker service.
    """
    current = time.time() if now is None else now
    hourly = _HOURLY_EVENTS[client_id]
    daily = _DAILY_EVENTS[client_id]
    _drop_older_than(hourly, current - 3600)
    _drop_older_than(daily, current - 86400)

    if len(hourly) >= hourly_limit:
        retry_after = int(max(1, 3600 - (current - hourly[0])))
        return False, retry_after, "hourly scan limit reached"
    if len(daily) >= daily_limit:
        retry_after = int(max(1, 86400 - (current - daily[0])))
        return False, retry_after, "daily scan limit reached"

    hourly.append(current)
    daily.append(current)
    return True, 0, "ok"


def _drop_older_than(events: deque[float], cutoff: float) -> None:
    while events and events[0] <= cutoff:
        events.popleft()
