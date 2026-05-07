"""Tool execution dispatch mixin for DefaultAgent."""
from __future__ import annotations

import inspect
import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from aegis.models import AttackPayload, ToolCall
from aegis.optional_dependencies import OptionalDependencyError, missing_dependency_error

logger = logging.getLogger(__name__)

_URL_PATTERN: re.Pattern[str] = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_QUOTED_PATH_PATTERN: re.Pattern[str] = re.compile(r"[\"']([^\"']+)[\"']")
_MAX_TOOL_ITERATIONS = 5

_PARAM_DEFAULTS: dict[str, object] = {
    "path": ".",
    "url": "https://example.com",
    "code": "print('hello from aegis')",
    "sql": "SELECT * FROM records LIMIT 5",
    "to": "audit@example.com",
    "subject": "AEGIS test message",
    "body": "Automated tool path verification.",
    "data": "test-record",
    "limit": 20,
    "timeout_seconds": 3,
    "content": "test content",
    "payload": {},
}


class _AgentToolsMixin:
    """Mixin: MCP tool execution in offline and LLM-driven modes."""

    def _execute_tools(self, payload: AttackPayload) -> list[ToolCall]:
        if self._provider_name == "offline":
            return self._execute_tools_offline(payload)
        return self._execute_tools_llm(payload)

    def _execute_tools_offline(self, payload: AttackPayload) -> list[ToolCall]:
        tool_calls: list[ToolCall] = []
        plans = self._tool_plans(payload)
        run_state: dict[str, Any] = {"tool_history": [], "tool_call_count": 0}

        for tool_name, args in plans:
            blocked, blocked_by, blocked_reason = self._inspect_tool_call(tool_name, args, run_state)
            tool_fn = self._tool_registry.get(tool_name)
            if tool_fn is None:
                run_state["tool_call_count"] += 1
                continue
            if blocked:
                result_str = f"Tool blocked by {blocked_by}: {blocked_reason}"
                tool_calls.append(
                    ToolCall(
                        tool_name=tool_name,
                        parameters=args,
                        result=result_str,
                        timestamp=datetime.now(UTC),
                    )
                )
                run_state["tool_call_count"] += 1
                continue
            try:
                result_obj = tool_fn(**args)
                result_str = self._normalize_tool_result(result_obj)
            except Exception as exc:
                result_str = f"Tool error: {exc}"
            tool_calls.append(
                ToolCall(
                    tool_name=tool_name,
                    parameters=args,
                    result=result_str,
                    timestamp=datetime.now(UTC),
                )
            )
            run_state["tool_history"].append(tool_name)
            run_state["tool_call_count"] += 1
        self._append_injected_tool_output(tool_calls)
        return tool_calls

    def _execute_tools_llm(self, payload: AttackPayload) -> list[ToolCall]:
        if not self._supports_model_tool_calling():
            logger.info(
                "Provider %s does not support model-driven tool calling in this adapter; "
                "using deterministic dispatcher",
                self._provider_name,
            )
            return self._execute_tools_offline(payload)
        try:
            return self._execute_tools_langchain(payload)
        except OptionalDependencyError:
            raise
        except Exception as exc:
            logger.warning("LLM tool-calling failed, falling back to offline: %s", exc)
            return self._execute_tools_offline(payload)

    def _execute_tools_langchain(self, payload: AttackPayload) -> list[ToolCall]:
        try:
            from langchain_core.messages import ToolMessage
        except ImportError as exc:
            raise missing_dependency_error(
                feature="LangChain tool execution",
                extra="local",
                packages=["langchain", "langchain-community"],
            ) from exc

        langchain_tools = self._build_langchain_tools()
        if not langchain_tools:
            return self._execute_tools_offline(payload)

        tool_map = {t.name: t for t in langchain_tools}
        model = self._build_tool_calling_model()
        model_with_tools = model.bind_tools(langchain_tools)
        messages = self._build_chat_messages(payload)

        tool_calls: list[ToolCall] = []
        run_state: dict[str, Any] = {"tool_history": [], "tool_call_count": 0}
        for _ in range(_MAX_TOOL_ITERATIONS):
            ai_message = model_with_tools.invoke(messages)
            messages.append(ai_message)

            tool_call_items = getattr(ai_message, "tool_calls", None)
            if not tool_call_items:
                break

            for tc in tool_call_items:
                name = tc["name"]
                args = tc.get("args", {})
                blocked, blocked_by, blocked_reason = self._inspect_tool_call(name, args, run_state)
                tool = tool_map.get(name)
                if tool is None:
                    run_state["tool_call_count"] += 1
                    continue
                if blocked:
                    result_str = f"Tool blocked by {blocked_by}: {blocked_reason}"
                    tool_calls.append(
                        ToolCall(
                            tool_name=name,
                            parameters=args,
                            result=result_str,
                            timestamp=datetime.now(UTC),
                        )
                    )
                    messages.append(
                        ToolMessage(content=result_str, tool_call_id=tc.get("id", name))
                    )
                    run_state["tool_call_count"] += 1
                    continue
                try:
                    result = tool.invoke(args)
                    result_str = self._normalize_tool_result(result)
                except Exception as exc:
                    result_str = f"Tool error: {exc}"
                tool_calls.append(
                    ToolCall(
                        tool_name=name,
                        parameters=args,
                        result=result_str,
                        timestamp=datetime.now(UTC),
                    )
                )
                messages.append(
                    ToolMessage(content=result_str, tool_call_id=tc.get("id", name))
                )
                run_state["tool_history"].append(name)
                run_state["tool_call_count"] += 1

        self._append_injected_tool_output(tool_calls)
        return tool_calls

    def _build_langchain_tools(self) -> list:
        try:
            from langchain_core.tools import StructuredTool
        except ImportError as exc:
            raise missing_dependency_error(
                feature="LangChain tool execution",
                extra="local",
                packages=["langchain", "langchain-community"],
            ) from exc

        tools = []
        for name, fn in self._tool_registry.items():
            try:
                tool = StructuredTool.from_function(fn, name=name)
                tools.append(tool)
            except Exception as exc:
                logger.warning("Failed to build LangChain tool '%s': %s", name, exc)
        return tools

    def _tool_plans(self, payload: AttackPayload) -> list[tuple[str, dict[str, Any]]]:
        if not payload.messages:
            return []

        last_user_text = str(payload.messages[-1].get("content", ""))
        content = last_user_text.lower()
        plans: list[tuple[str, dict[str, Any]]] = []

        for tool_name, tool_fn in self._tool_registry.items():
            name_lower = tool_name.lower()
            spaced = tool_name.replace("_", " ").lower()
            if name_lower not in content and spaced not in content:
                continue
            args = self._extract_tool_args(tool_fn, last_user_text)
            plans.append((tool_name, args))

        planned_names = {name for name, _args in plans}
        target_tools = payload.target_tools or []
        if "code_exec" in {str(name).lower() for name in target_tools}:
            tool_fn = self._tool_registry.get("execute_code")
            if tool_fn is not None and "execute_code" not in planned_names:
                plans.append(("execute_code", self._extract_tool_args(tool_fn, last_user_text)))

        return plans

    def _extract_tool_args(
        self, tool_fn: Callable[..., object], message: str
    ) -> dict[str, Any]:
        sig = inspect.signature(tool_fn)
        args: dict[str, Any] = {}
        for param_name, param in sig.parameters.items():
            extracted = self._extract_param_value(param_name, message)
            if extracted is not None:
                args[param_name] = extracted
            elif param.default is inspect.Parameter.empty:
                default = _PARAM_DEFAULTS.get(param_name)
                if default is not None:
                    args[param_name] = default
        return args

    def _extract_param_value(self, param_name: str, message: str) -> Any | None:
        if param_name == "path":
            match = _QUOTED_PATH_PATTERN.search(message)
            return match.group(1) if match else None
        if param_name == "url":
            match = _URL_PATTERN.search(message)
            return match.group(0) if match else None
        if param_name in ("code", "sql"):
            backtick = re.search(r"`([^`]+)`", message)
            if backtick:
                return backtick.group(1)
            if param_name == "code":
                code_match = re.search(
                    r"\b(?:execute|run):\s*(.+)$",
                    message,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                if code_match:
                    return code_match.group(1).strip()
                import_match = re.search(r"\bimport\s+.+$", message, flags=re.IGNORECASE | re.DOTALL)
                if import_match:
                    return import_match.group(0).strip()
            return None
        return None

    def _normalize_tool_result(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=True, default=str)
        except TypeError:
            return str(value)

    def _append_injected_tool_output(self, tool_calls: list[ToolCall]) -> None:
        if self._pending_tool_output is not None:
            tool_calls.append(
                ToolCall(
                    tool_name="injected_tool_output",
                    parameters={"source": "inject_context"},
                    result=self._pending_tool_output,
                    timestamp=datetime.now(UTC),
                )
            )
            self._pending_tool_output = None
