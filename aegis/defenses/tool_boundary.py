"""Day 8 tool boundary defense."""
from __future__ import annotations

import json
import re
from typing import Any

from aegis.interfaces.agent import AgentInterface
from aegis.interfaces.defense import Defense

_DEFAULT_PARAM_BLOCK_PATTERNS: tuple[str, ...] = (
    r"(?:\$\(|`|;\s*|&&|\|\|)",
    r"(?:\.\./|/etc/passwd|/etc/shadow)",
    r"(?:drop\s+table|union\s+select|;\s*select)",
)

_SUSPICIOUS_CHAIN_PATTERN = re.compile(
    r"(read_file|query_db|read_inbox).{0,120}(send_email|post_request|fetch_url)",
    re.IGNORECASE | re.DOTALL,
)


class ToolBoundaryDefense(Defense):
    """Defense for tool allowlisting, parameter checks, and call rate limiting."""

    name = "tool_boundary"
    description = (
        "Restricts tool invocation sequences, validates tool parameters, and rate-limits "
        "tool calls per run."
    )

    def __init__(
        self,
        *,
        strict: bool = True,
        max_calls_per_run: int = 5,
        allowed_tools: list[str] | None = None,
        allowed_sequences: dict[str, list[str]] | None = None,
        param_block_patterns: list[str] | None = None,
    ) -> None:
        self._strict = bool(strict)
        self._max_calls_per_run = max(1, int(max_calls_per_run))
        self._allowed_tools = {str(name) for name in (allowed_tools or [])}
        self._allowed_sequences = {
            str(src): [str(dst) for dst in dsts]
            for src, dsts in (allowed_sequences or {}).items()
        }
        patterns = param_block_patterns or list(_DEFAULT_PARAM_BLOCK_PATTERNS)
        self._param_patterns = tuple(re.compile(p, re.IGNORECASE) for p in patterns)

    def apply(self, agent: AgentInterface) -> None:
        agent.enable_defense(
            self.name,
            {
                "enabled": True,
                "strict": self._strict,
                "max_calls_per_run": self._max_calls_per_run,
                "allowed_tools": sorted(self._allowed_tools),
                "allowed_sequences": self._allowed_sequences,
                "param_block_patterns": [p.pattern for p in self._param_patterns],
            },
        )

    def remove(self, agent: AgentInterface) -> None:
        agent.disable_defense(self.name)

    def inspect(self, input_data: str | dict[str, Any]) -> tuple[bool, str]:
        if isinstance(input_data, str):
            if _SUSPICIOUS_CHAIN_PATTERN.search(input_data):
                return True, "suspicious tool chaining requested"
            return False, ""

        if not isinstance(input_data, dict):
            return False, ""

        event = str(input_data.get("event", ""))
        if event == "input":
            text = str(input_data.get("text", ""))
            if _SUSPICIOUS_CHAIN_PATTERN.search(text):
                return True, "suspicious tool chaining requested"
            return False, ""

        if event != "tool_call":
            return False, ""

        tool_name = str(input_data.get("tool_name", ""))
        previous_tool = input_data.get("previous_tool")
        tool_call_count = int(input_data.get("tool_call_count", 0))
        parameters = input_data.get("parameters", {})

        if tool_call_count > self._max_calls_per_run:
            return True, "tool call rate limit exceeded"

        if self._allowed_tools and tool_name not in self._allowed_tools:
            return True, f"tool '{tool_name}' not in allowlist"

        if previous_tool is not None:
            prev = str(previous_tool)
            allowed_next = self._allowed_sequences.get(prev)
            if allowed_next is not None and tool_name not in allowed_next:
                return True, f"tool sequence '{prev}->{tool_name}' not allowed"

        serialized_params = self._serialize_params(parameters)
        for pattern in self._param_patterns:
            if pattern.search(serialized_params):
                return True, "suspicious tool parameters detected"

        if self._strict and len(serialized_params) > 20_000:
            return True, "tool parameters exceed strict boundary size"

        return False, ""

    def _serialize_params(self, parameters: Any) -> str:
        if isinstance(parameters, str):
            return parameters
        try:
            return json.dumps(parameters, sort_keys=True)
        except TypeError:
            return str(parameters)
