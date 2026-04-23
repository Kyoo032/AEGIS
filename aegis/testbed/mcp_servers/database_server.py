"""Mock SQLite database MCP server."""
from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from fastmcp import FastMCP
except ImportError:
    FastMCP = None

server = FastMCP("database") if FastMCP is not None else None

_DB_PATH = Path("/tmp/aegis_mcp.db")
_CONN = sqlite3.connect(_DB_PATH, check_same_thread=False)
_LOCK = threading.RLock()
_MAX_ROWS = 1000
_QUERY_TIMEOUT_SECONDS = 2.0
_CONN.execute(
    "CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL)"
)
_CONN.commit()


def configure_security(config: dict[str, Any]) -> None:
    """Apply database server security policy."""
    global _MAX_ROWS, _QUERY_TIMEOUT_SECONDS
    max_rows = config.get("database_max_rows")
    if isinstance(max_rows, int) and max_rows > 0:
        _MAX_ROWS = max_rows

    timeout_seconds = config.get("database_timeout_seconds")
    if isinstance(timeout_seconds, int | float) and timeout_seconds > 0:
        _QUERY_TIMEOUT_SECONDS = float(timeout_seconds)


def _ensure_read_only_select(sql: str) -> None:
    normalized = " ".join(sql.strip().lower().split())
    if not normalized.startswith("select"):
        raise ValueError("Only SELECT queries are allowed.")
    if ";" in normalized:
        raise ValueError("Only a single SELECT statement is allowed.")
    blocked_tokens = ("pragma", "attach", "detach", "vacuum", "/*", "--")
    if any(token in normalized for token in blocked_tokens):
        raise ValueError("Blocked SQL token in query.")


def insert_record(data: str) -> str:
    """Insert a text record into the mock SQLite table."""
    with _LOCK:
        cur = _CONN.execute("INSERT INTO records(data) VALUES (?)", (data,))
        _CONN.commit()
    return f"Inserted record id={cur.lastrowid}"


def query_db(sql: str) -> list[dict[str, object]]:
    """Execute a read-only SELECT query and return row dicts."""
    _ensure_read_only_select(sql)

    deadline = time.monotonic() + _QUERY_TIMEOUT_SECONDS

    def _progress_handler() -> int:
        return 1 if time.monotonic() > deadline else 0

    with _LOCK:
        _CONN.set_progress_handler(_progress_handler, 1000)
        try:
            cur = _CONN.execute(sql)
            cols = [d[0] for d in cur.description or []]
            rows = cur.fetchmany(_MAX_ROWS + 1)
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc).lower():
                raise TimeoutError("Database query timed out.") from exc
            raise
        finally:
            _CONN.set_progress_handler(None, 0)

    if len(rows) > _MAX_ROWS:
        rows = rows[:_MAX_ROWS]

    return [dict(zip(cols, row, strict=False)) for row in rows]


TOOLS: dict[str, Callable[..., object]] = {
    "insert_record": insert_record,
    "query_db": query_db,
}

if server is not None:
    server.tool(insert_record)
    server.tool(query_db)


def get_tools() -> dict[str, Callable[..., object]]:
    """Return callable tool map for agent-side local invocation."""
    return dict(TOOLS)
