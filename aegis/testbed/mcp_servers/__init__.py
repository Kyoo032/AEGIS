"""MCP server implementations and local tool registry."""
from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from importlib import import_module
from typing import Any

_SERVER_MODULES: dict[str, str] = {
    "filesystem": "aegis.testbed.mcp_servers.filesystem_server",
    "http": "aegis.testbed.mcp_servers.http_server",
    "email": "aegis.testbed.mcp_servers.email_server",
    "database": "aegis.testbed.mcp_servers.database_server",
    "code_exec": "aegis.testbed.mcp_servers.code_exec_server",
    "evil": "aegis.testbed.mcp_servers.evil_server",
}


def load_tool_registry(
    server_names: list[str],
    security_config: dict[str, Any] | None = None,
) -> dict[str, Callable[..., object]]:
    """Load tools for the configured server list."""
    requested = tuple(sorted({str(name) for name in server_names}))
    config = security_config or {}
    _apply_server_policy(requested, config)
    return dict(_cached_registry(requested))


@lru_cache(maxsize=32)
def _cached_registry(server_names: tuple[str, ...]) -> dict[str, Callable[..., object]]:
    registry: dict[str, Callable[..., object]] = {}
    for name in server_names:
        module_path = _SERVER_MODULES.get(name)
        if module_path is None:
            continue
        module = import_module(module_path)
        module_tools = module.get_tools()
        registry.update(module_tools)
    return registry


def _apply_server_policy(server_names: tuple[str, ...], security: dict[str, Any]) -> None:
    for name in server_names:
        module_path = _SERVER_MODULES.get(name)
        if module_path is None:
            continue
        module = import_module(module_path)
        configure = getattr(module, "configure_security", None)
        if callable(configure):
            configure(security)


__all__ = ["load_tool_registry"]
