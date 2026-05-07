"""Defense wiring and inspection mixin for DefaultAgent."""
from __future__ import annotations

import logging
from typing import Any

from aegis.models import AttackPayload

logger = logging.getLogger(__name__)


class _AgentDefensesMixin:
    """Mixin: defense construction, input/tool/output inspection, and manifest checks."""

    def _tool_manifest(self) -> dict[str, str]:
        from aegis.defenses.mcp_integrity import build_tool_manifest

        return build_tool_manifest(self._tool_registry)

    def _enabled_defenses(self) -> list[tuple[str, dict[str, Any]]]:
        return [(name, cfg) for name, cfg in sorted(self._defenses.items())]

    def _build_defense(self, defense_name: str, config: dict[str, Any]) -> Any | None:
        if defense_name == "input_validator":
            from aegis.defenses.input_validator import InputValidatorDefense

            return InputValidatorDefense(
                strict=bool(config.get("strict", False)),
                max_input_chars=int(config.get("max_input_chars", 8_000)),
            )
        if defense_name == "output_filter":
            from aegis.defenses.output_filter import OutputFilterDefense

            return OutputFilterDefense(block_on_match=bool(config.get("block_on_match", True)))
        if defense_name == "tool_boundary":
            from aegis.defenses.tool_boundary import ToolBoundaryDefense

            return ToolBoundaryDefense(
                strict=bool(config.get("strict", True)),
                max_calls_per_run=int(config.get("max_calls_per_run", 5)),
                allowed_tools=list(config.get("allowed_tools") or []),
                allowed_sequences=dict(config.get("allowed_sequences") or {}),
                param_block_patterns=list(config.get("param_block_patterns") or []),
            )
        if defense_name == "mcp_integrity":
            from aegis.defenses.mcp_integrity import MCPIntegrityDefense

            return MCPIntegrityDefense(
                strict=bool(config.get("strict", True)),
                allow_new_tools=bool(config.get("allow_new_tools", False)),
                verify_doc_hash=bool(config.get("verify_doc_hash", True)),
            )
        if defense_name == "permission_enforcer":
            from aegis.defenses.permission_enforcer import PermissionEnforcerDefense

            return PermissionEnforcerDefense(
                mode=str(config.get("mode", "standard")),
                allowed_tools=list(config.get("allowed_tools") or []),
                tool_permissions=dict(config.get("tool_permissions") or {}),
                forbidden_cross_tool_flows=list(config.get("forbidden_cross_tool_flows") or []),
            )
        return None

    def _inspect_pre_run(self, payload: AttackPayload) -> tuple[bool, str | None, str]:
        _ = payload
        current_manifest = self._tool_manifest()
        for defense_name, config in self._enabled_defenses():
            if defense_name != "mcp_integrity":
                continue
            defense = self._build_defense(defense_name, config)
            if defense is None:
                continue
            baseline_manifest = config.get("baseline_manifest")
            if not isinstance(baseline_manifest, dict):
                baseline_manifest = current_manifest
                config["baseline_manifest"] = baseline_manifest
            blocked, reason = defense.inspect(
                {
                    "event": "manifest_check",
                    "baseline_manifest": baseline_manifest,
                    "current_manifest": current_manifest,
                }
            )
            if blocked:
                return True, defense_name, reason
        return False, None, ""

    def _inspect_input(self, payload: AttackPayload) -> tuple[bool, str | None, str]:
        candidate = self._latest_user_message(payload)
        for defense_name, config in self._enabled_defenses():
            if defense_name not in {"input_validator", "tool_boundary"}:
                continue
            defense = self._build_defense(defense_name, config)
            if defense is None:
                continue
            if defense_name == "input_validator":
                blocked, reason = defense.inspect(candidate)
            else:
                blocked, reason = defense.inspect({"event": "input", "text": candidate})
            if blocked:
                return True, defense_name, reason
        return False, None, ""

    def _inspect_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        run_state: dict[str, Any],
    ) -> tuple[bool, str | None, str]:
        tool_history = list(run_state.get("tool_history", []))
        previous_tool = tool_history[-1] if tool_history else None
        next_count = int(run_state.get("tool_call_count", 0)) + 1
        current_manifest = self._tool_manifest()

        for defense_name, config in self._enabled_defenses():
            if defense_name not in {"tool_boundary", "permission_enforcer", "mcp_integrity"}:
                continue
            defense = self._build_defense(defense_name, config)
            if defense is None:
                continue
            if defense_name == "mcp_integrity":
                baseline_manifest = config.get("baseline_manifest")
                if not isinstance(baseline_manifest, dict):
                    baseline_manifest = current_manifest
                    config["baseline_manifest"] = baseline_manifest
                blocked, reason = defense.inspect(
                    {
                        "event": "manifest_check",
                        "baseline_manifest": baseline_manifest,
                        "current_manifest": current_manifest,
                    }
                )
            else:
                blocked, reason = defense.inspect(
                    {
                        "event": "tool_call",
                        "tool_name": tool_name,
                        "parameters": args,
                        "previous_tool": previous_tool,
                        "tool_history": tool_history,
                        "tool_call_count": next_count,
                    }
                )
            if blocked:
                return True, defense_name, reason
        return False, None, ""

    def _apply_output_defenses(self, output: str) -> tuple[str, list[str]]:
        current = output
        reasons: list[str] = []
        for defense_name, config in self._enabled_defenses():
            if defense_name != "output_filter":
                continue
            defense = self._build_defense(defense_name, config)
            if defense is None:
                continue
            if defense_name == "output_filter":
                block_on_match = bool(config.get("block_on_match", True))
                blocked, reason = defense.inspect(current)
                if not blocked:
                    continue
                reasons.append(reason)
                if block_on_match:
                    return "Response blocked by output_filter.", reasons
                current = defense.sanitize(current)
        return current, reasons

    def _active_defense_name(self) -> str | None:
        if not self._defenses:
            return None
        return sorted(self._defenses.keys())[0]

    def _latest_user_message(self, payload: AttackPayload) -> str:
        for message in reversed(payload.messages):
            if str(message.get("role", "user")) == "user":
                return str(message.get("content", ""))

        if payload.messages:
            return str(payload.messages[-1].get("content", ""))
        return ""
