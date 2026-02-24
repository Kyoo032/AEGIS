"""Day 9 MCP integrity defense."""
from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable, Mapping
from typing import Any

from aegis.interfaces.agent import AgentInterface
from aegis.interfaces.defense import Defense


def build_tool_manifest(tool_registry: Mapping[str, Callable[..., object]]) -> dict[str, str]:
    """Return a stable digest map for registered tools."""
    manifest: dict[str, str] = {}
    for tool_name in sorted(tool_registry):
        tool_fn = tool_registry[tool_name]
        try:
            signature = str(inspect.signature(tool_fn))
        except (TypeError, ValueError):
            signature = "()"
        doc = inspect.getdoc(tool_fn) or ""
        doc_hash = hashlib.sha256(doc.encode("utf-8")).hexdigest()[:16]
        manifest[str(tool_name)] = f"{signature}|{doc_hash}"
    return manifest


class MCPIntegrityDefense(Defense):
    """Detects MCP tool manifest drift and unexpected tool changes."""

    name = "mcp_integrity"
    description = (
        "Verifies MCP tool definition integrity via manifest hashing and flags unexpected "
        "tool additions or changes."
    )

    def __init__(
        self,
        *,
        strict: bool = True,
        allow_new_tools: bool = False,
        verify_doc_hash: bool = True,
    ) -> None:
        self._strict = bool(strict)
        self._allow_new_tools = bool(allow_new_tools)
        self._verify_doc_hash = bool(verify_doc_hash)

    def apply(self, agent: AgentInterface) -> None:
        registry = getattr(agent, "_tool_registry", {})
        baseline = build_tool_manifest(registry) if isinstance(registry, Mapping) else {}
        agent.enable_defense(
            self.name,
            {
                "enabled": True,
                "strict": self._strict,
                "allow_new_tools": self._allow_new_tools,
                "verify_doc_hash": self._verify_doc_hash,
                "baseline_manifest": baseline,
            },
        )

    def remove(self, agent: AgentInterface) -> None:
        agent.disable_defense(self.name)

    def inspect(self, input_data: str | dict[str, Any]) -> tuple[bool, str]:
        if not isinstance(input_data, dict):
            return False, ""

        if str(input_data.get("event", "")) != "manifest_check":
            return False, ""

        baseline = input_data.get("baseline_manifest", {})
        current = input_data.get("current_manifest", {})
        if not isinstance(baseline, dict) or not isinstance(current, dict):
            return True, "invalid MCP manifest input"
        if not baseline:
            return False, ""

        baseline_tools = set(baseline.keys())
        current_tools = set(current.keys())

        added = sorted(current_tools - baseline_tools)
        removed = sorted(baseline_tools - current_tools)
        changed = sorted(
            tool for tool in baseline_tools & current_tools if baseline[tool] != current[tool]
        )

        if not self._verify_doc_hash:
            changed = []

        reasons: list[str] = []
        if removed:
            reasons.append(f"missing tools: {', '.join(removed)}")
        if changed:
            reasons.append(f"modified tools: {', '.join(changed)}")
        if added and not self._allow_new_tools:
            reasons.append(f"unexpected tools: {', '.join(added)}")

        if not reasons:
            return False, ""

        if self._strict:
            return True, "; ".join(reasons)
        return False, "; ".join(reasons)
