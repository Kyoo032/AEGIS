"""Mock email MCP server.

Stores emails in-memory for deterministic testing.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

try:
    from fastmcp import FastMCP
except ImportError:
    FastMCP = None

server = FastMCP("email") if FastMCP is not None else None

_INBOX: list[dict[str, str]] = []
_MAX_INBOX_ITEMS = 200
_MAX_BODY_CHARS = 20_000
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def configure_security(config: dict[str, Any]) -> None:
    """Apply email server security policy."""
    global _MAX_INBOX_ITEMS, _MAX_BODY_CHARS
    max_items = config.get("email_max_inbox_items")
    if isinstance(max_items, int) and max_items > 0:
        _MAX_INBOX_ITEMS = max_items

    max_body_chars = config.get("email_max_body_chars")
    if isinstance(max_body_chars, int) and max_body_chars > 0:
        _MAX_BODY_CHARS = max_body_chars


def send_email(to: str, subject: str, body: str) -> str:
    """Store a mock email in the in-memory inbox."""
    if not _EMAIL_PATTERN.match(to):
        raise ValueError("Invalid recipient email format.")
    if len(body) > _MAX_BODY_CHARS:
        raise ValueError(f"Email body exceeds max size ({_MAX_BODY_CHARS} chars).")

    _INBOX.append(
        {
            "to": to,
            "subject": subject,
            "body": body,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    if len(_INBOX) > _MAX_INBOX_ITEMS:
        del _INBOX[0 : len(_INBOX) - _MAX_INBOX_ITEMS]

    return f"Email queued to {to}"


def read_inbox(limit: int = 20) -> list[dict[str, str]]:
    """Return the most recent mock inbox entries."""
    if limit < 0:
        raise ValueError("limit must be >= 0")
    return list(_INBOX[-limit:])


def clear_inbox() -> str:
    """Clear all mock inbox entries."""
    _INBOX.clear()
    return "Inbox cleared"


TOOLS: dict[str, Callable[..., object]] = {
    "send_email": send_email,
    "read_inbox": read_inbox,
    "clear_inbox": clear_inbox,
}

if server is not None:
    server.tool(send_email)
    server.tool(read_inbox)
    server.tool(clear_inbox)


def get_tools() -> dict[str, Callable[..., object]]:
    """Return callable tool map for agent-side local invocation."""
    return dict(TOOLS)
