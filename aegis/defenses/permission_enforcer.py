"""Day 9 permission enforcer defense."""
from __future__ import annotations

from typing import Any

from aegis.interfaces.agent import AgentInterface
from aegis.interfaces.defense import Defense

_DEFAULT_TOOL_PERMISSIONS: dict[str, str] = {
    "list_directory": "read",
    "read_file": "read",
    "query_db": "read",
    "read_inbox": "read",
    "fetch_url": "network_read",
    "write_file": "write",
    "delete_file": "write",
    "insert_record": "write",
    "send_email": "network_write",
    "post_request": "network_write",
    "record_analytics": "network_write",
    "execute_code": "exec",
}

_DEFAULT_FORBIDDEN_FLOWS: list[dict[str, list[str]]] = [
    {
        "from_tools": ["read_file", "query_db", "read_inbox"],
        "to_tools": ["send_email", "post_request", "fetch_url"],
    }
]

_WRITE_PERMISSIONS: frozenset[str] = frozenset({"write", "network_write", "exec"})


class PermissionEnforcerDefense(Defense):
    """Least-privilege enforcement and cross-tool flow controls."""

    name = "permission_enforcer"
    description = (
        "Applies least-privilege tool policy, read/write scope controls, and "
        "cross-tool data-flow restrictions."
    )

    def __init__(
        self,
        *,
        mode: str = "standard",
        allowed_tools: list[str] | None = None,
        tool_permissions: dict[str, str] | None = None,
        forbidden_cross_tool_flows: list[dict[str, list[str]]] | None = None,
    ) -> None:
        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in {"standard", "read_only", "restricted"}:
            normalized_mode = "standard"
        self._mode = normalized_mode
        self._allowed_tools = {str(name) for name in (allowed_tools or [])}
        self._tool_permissions = dict(_DEFAULT_TOOL_PERMISSIONS)
        if tool_permissions:
            self._tool_permissions.update({
                str(tool): str(permission) for tool, permission in tool_permissions.items()
            })
        self._forbidden_flows = forbidden_cross_tool_flows or list(_DEFAULT_FORBIDDEN_FLOWS)

    def apply(self, agent: AgentInterface) -> None:
        agent.enable_defense(
            self.name,
            {
                "enabled": True,
                "mode": self._mode,
                "allowed_tools": sorted(self._allowed_tools),
                "tool_permissions": dict(self._tool_permissions),
                "forbidden_cross_tool_flows": list(self._forbidden_flows),
            },
        )

    def remove(self, agent: AgentInterface) -> None:
        agent.disable_defense(self.name)

    def inspect(self, input_data: str | dict[str, Any]) -> tuple[bool, str]:
        if not isinstance(input_data, dict):
            return False, ""
        if str(input_data.get("event", "")) != "tool_call":
            return False, ""

        tool_name = str(input_data.get("tool_name", ""))
        tool_history = [str(name) for name in input_data.get("tool_history", [])]

        if self._allowed_tools and tool_name not in self._allowed_tools:
            return True, f"tool '{tool_name}' is not permitted"

        permission = self._tool_permissions.get(tool_name, "unknown")
        if self._mode == "read_only" and permission in _WRITE_PERMISSIONS:
            return True, f"tool '{tool_name}' violates read-only scope"
        if self._mode == "restricted" and permission != "read":
            return True, f"tool '{tool_name}' blocked in restricted mode"

        for flow in self._forbidden_flows:
            from_tools = {str(name) for name in flow.get("from_tools", [])}
            to_tools = {str(name) for name in flow.get("to_tools", [])}
            if tool_name in to_tools and any(prev in from_tools for prev in tool_history):
                return True, f"cross-tool flow blocked: {tool_history[-1]}->{tool_name}"

        return False, ""
