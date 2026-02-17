"""File access MCP server.

Provides a small set of filesystem tools behind a safe root directory.
Tools are registered on a FastMCP server and can also be called directly
by the local testbed agent.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

server = FastMCP("filesystem")

_SAFE_ROOT = Path("/tmp/aegis_fs")
_MAX_READ_BYTES = 1_048_576
_MAX_WRITE_BYTES = 1_048_576
_SAFE_ROOT.mkdir(parents=True, exist_ok=True)


def configure_security(config: dict[str, Any]) -> None:
    """Apply filesystem server security policy."""
    global _SAFE_ROOT, _MAX_READ_BYTES, _MAX_WRITE_BYTES

    safe_root = config.get("filesystem_safe_root")
    if isinstance(safe_root, str) and safe_root:
        _SAFE_ROOT = Path(safe_root).resolve()
    _SAFE_ROOT.mkdir(parents=True, exist_ok=True)

    read_limit = config.get("filesystem_max_read_bytes")
    if isinstance(read_limit, int) and read_limit > 0:
        _MAX_READ_BYTES = read_limit

    write_limit = config.get("filesystem_max_write_bytes")
    if isinstance(write_limit, int) and write_limit > 0:
        _MAX_WRITE_BYTES = write_limit


def _resolve_safe_path(path: str) -> Path:
    """Resolve user path under the safe root, blocking traversal."""
    candidate = (_SAFE_ROOT / path).resolve()
    if not candidate.is_relative_to(_SAFE_ROOT.resolve()):
        raise ValueError("Path escapes filesystem safe root.")
    return candidate


def read_file(path: str) -> str:
    """Read a UTF-8 text file from the safe root."""
    resolved = _resolve_safe_path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"File does not exist: {path}")
    if resolved.is_dir():
        raise IsADirectoryError(f"Path is a directory: {path}")
    if not resolved.is_file():
        raise ValueError(f"Path is not a regular file: {path}")
    raw = resolved.read_bytes()
    if len(raw) > _MAX_READ_BYTES:
        raise ValueError(f"File exceeds max read size ({_MAX_READ_BYTES} bytes): {path}")
    return raw.decode("utf-8")


def write_file(path: str, content: str) -> str:
    """Write UTF-8 text to a file under the safe root."""
    payload = content.encode("utf-8")
    if len(payload) > _MAX_WRITE_BYTES:
        raise ValueError(f"Content exceeds max write size ({_MAX_WRITE_BYTES} bytes)")
    resolved = _resolve_safe_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_bytes(payload)
    return f"Wrote {len(payload)} bytes to {path}"


def list_directory(path: str = ".") -> list[str]:
    """List entries under a safe-root directory."""
    resolved = _resolve_safe_path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"Directory does not exist: {path}")
    if not resolved.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {path}")
    return sorted(entry.name for entry in resolved.iterdir())


def delete_file(path: str) -> str:
    """Delete a file under the safe root."""
    resolved = _resolve_safe_path(path)
    if not resolved.exists():
        raise FileNotFoundError(f"File does not exist: {path}")
    if resolved.is_dir():
        raise IsADirectoryError(f"Path is a directory: {path}")
    resolved.unlink()
    return f"Deleted {path}"


TOOLS: dict[str, Callable[..., object]] = {
    "read_file": read_file,
    "write_file": write_file,
    "list_directory": list_directory,
    "delete_file": delete_file,
}

server.tool(read_file)
server.tool(write_file)
server.tool(list_directory)
server.tool(delete_file)


def get_tools() -> dict[str, Callable[..., object]]:
    """Return callable tool map for agent-side local invocation."""
    return dict(TOOLS)
