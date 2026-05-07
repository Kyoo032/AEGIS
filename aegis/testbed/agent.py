"""Victim agent testbed implementation."""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from aegis.interfaces.agent import AgentInterface
from aegis.models import AgentResponse, AttackPayload
from aegis.testbed.agent_config import _AgentConfigMixin
from aegis.testbed.agent_defenses import _AgentDefensesMixin
from aegis.testbed.agent_output import _AgentOutputMixin
from aegis.testbed.agent_providers import _HOSTED_PROVIDER_MODES, _AgentProvidersMixin
from aegis.testbed.agent_tools import _AgentToolsMixin
from aegis.testbed.mcp_servers import load_tool_registry

if TYPE_CHECKING:
    from aegis.testbed.kb.runtime import KnowledgeBaseRuntime

logger = logging.getLogger(__name__)


class DefaultAgent(
    _AgentConfigMixin,
    _AgentProvidersMixin,
    _AgentToolsMixin,
    _AgentDefensesMixin,
    _AgentOutputMixin,
    AgentInterface,
):
    """Default local agent with MCP tool execution and provider fallbacks."""

    def __init__(self, config: str | dict[str, Any] | None = None) -> None:
        self._defense_defaults: dict[str, dict[str, Any]] = {}
        self._config, profile_defenses = self._resolve_testbed_config(config)
        self._security = dict(self._config.get("security", {}))
        self._memory_max_turns = max(1, int(self._security.get("memory_max_turns", 200)))
        self._rag_max_items = max(1, int(self._security.get("rag_max_items", 200)))
        self._defenses: dict[str, dict[str, Any]] = {}
        self._memory: list[dict[str, str]] = []
        self._injected_rag: list[str] = []
        self._pending_tool_output: str | None = None
        self._kb_runtime: KnowledgeBaseRuntime | None = None
        self._kb_mode = str(self._security.get("kb_mode", "baseline"))
        self._kb_context_lines: list[str] = []
        self._run_retrieval_trace: list[dict[str, Any]] = []
        self._tool_registry = load_tool_registry(
            self._configured_servers(),
            security_config=self._security,
        )
        self._init_kb_runtime()
        for defense_name in profile_defenses:
            self.enable_defense(defense_name, {})
        self._provider_name, self._provider_note = self._select_provider()
        logger.info(
            "DefaultAgent initialized profile=%s provider=%s note=%s tools=%d",
            self._config.get("agent_profile", "default"),
            self._provider_name,
            self._provider_note,
            len(self._tool_registry),
        )

    def run(self, payload: AttackPayload) -> AgentResponse:
        """Execute a payload.

        ``payload.messages`` may contain full conversation history for multi-turn tests.
        Memory is persisted across ``run()`` calls when memory is enabled, and cleared by
        ``reset()``.
        """
        start = time.perf_counter()
        self._kb_context_lines = []
        self._run_retrieval_trace = []

        if payload.injected_context:
            self.inject_context(payload.injected_context, method="rag")

        message_history = [dict(m) for m in payload.messages]
        blocked, blocking_defense, block_reason = self._inspect_pre_run(payload)
        if not blocked:
            blocked, blocking_defense, block_reason = self._inspect_input(payload)
        if blocked:
            blocked_by = blocking_defense or "defense"
            final_output = f"Request blocked by {blocked_by}: {block_reason}"
            message_history.append({"role": "assistant", "content": final_output})
            if self._config.get("memory_enabled", True):
                self._memory.extend(message_history[-2:])
                self._trim_memory()

            duration_ms = int((time.perf_counter() - start) * 1000)
            memory_state: dict[str, Any] | None = None
            if self._config.get("memory_enabled", True):
                memory_state = {"turns": list(self._memory)}

            return AgentResponse(
                payload_id=payload.id,
                agent_profile=str(self._config.get("agent_profile", "default")),
                messages=message_history,
                final_output=final_output,
                tool_calls=[],
                memory_state=memory_state,
                retrieval_trace=list(self._run_retrieval_trace),
                kb_state=self._kb_state_snapshot(),
                raw_llm_output=None,
                error=block_reason,
                duration_ms=duration_ms,
                defense_active=self._active_defense_name(),
            )

        self._prepare_kb_context(payload)
        tool_calls = self._execute_tools(payload)

        final_output, raw_llm_output, error = self._generate_output(payload, tool_calls)
        final_output, output_reasons = self._apply_output_defenses(final_output)
        if output_reasons:
            joined = "; ".join(output_reasons)
            error = f"{error}; {joined}" if error else joined
        assistant_message = {"role": "assistant", "content": final_output}
        message_history.append(assistant_message)

        if self._config.get("memory_enabled", True):
            self._memory.extend(message_history[-2:])
            self._trim_memory()

        duration_ms = int((time.perf_counter() - start) * 1000)
        logger.info(
            "Agent run complete payload_id=%s provider=%s tool_calls=%d duration_ms=%d",
            payload.id,
            self._provider_name,
            len(tool_calls),
            duration_ms,
        )
        memory_state = {"turns": list(self._memory)} if self._config.get("memory_enabled", True) else None

        return AgentResponse(
            payload_id=payload.id,
            agent_profile=str(self._config.get("agent_profile", "default")),
            messages=message_history,
            final_output=final_output,
            tool_calls=tool_calls,
            memory_state=memory_state,
            retrieval_trace=list(self._run_retrieval_trace),
            kb_state=self._kb_state_snapshot(),
            raw_llm_output=raw_llm_output,
            error=error,
            duration_ms=duration_ms,
            defense_active=self._active_defense_name(),
        )

    def reset(self) -> None:
        """Clear memory, injected context, and pending synthetic tool output."""
        self._memory.clear()
        self._injected_rag.clear()
        self._pending_tool_output = None
        self._kb_context_lines = []
        self._run_retrieval_trace = []
        if self._kb_runtime is not None:
            self._kb_runtime.reset_transient()

    def get_config(self) -> dict[str, Any]:
        """Return current agent configuration plus selected provider metadata."""
        out = dict(self._config)
        out["provider_selected"] = self._provider_name
        out["provider_note"] = self._provider_note
        return out

    def enable_defense(self, defense_name: str, config: dict[str, Any]) -> None:
        """Enable a named defense using caller-supplied config."""
        defaults = self._default_defense_config(defense_name)
        merged = self._merge_nested_dicts(defaults, dict(config))
        if defense_name == "mcp_integrity":
            merged.setdefault("baseline_manifest", self._tool_manifest())
        self._defenses[defense_name] = merged

    def disable_defense(self, defense_name: str) -> None:
        """Disable a defense if present."""
        self._defenses.pop(defense_name, None)

    def inject_context(self, context: str, method: str) -> None:
        """Inject attacker-controlled context into one of three testbed channels."""
        if method == "rag":
            if self._kb_runtime is not None and bool(self._config.get("rag_enabled", True)):
                self._kb_runtime.inject_context(context, method="rag")
            else:
                self._injected_rag.append(context)
                self._trim_rag()
            return
        if method == "memory":
            self._memory.append({"role": "system", "content": context})
            self._trim_memory()
            return
        if method == "tool_output":
            self._pending_tool_output = context
            return
        raise ValueError("method must be one of 'rag' | 'memory' | 'tool_output'")

    def health_check(self) -> dict[str, Any]:
        """Report provider, model, and MCP server connectivity health."""
        provider_cfg = self._config.get("provider", {})
        provider_mode = str(provider_cfg.get("mode", self._config.get("model_provider", "auto")))
        if provider_mode == "offline":
            ollama_ok, ollama_note = False, "skipped for provider mode 'offline'"
            hf_ok, hf_note = False, "skipped for provider mode 'offline'"
            hosted_ok, hosted_note = False, "skipped for provider mode 'offline'"
        elif provider_mode == "ollama":
            ollama_ok, ollama_note = self._check_ollama_health()
            hf_ok, hf_note = False, "skipped for provider mode 'ollama'"
            hosted_ok, hosted_note = False, "skipped for provider mode 'ollama'"
        elif provider_mode == "huggingface":
            ollama_ok, ollama_note = False, "skipped for provider mode 'huggingface'"
            hf_ok, hf_note = self._check_hf_token(provider_cfg)
            hosted_ok, hosted_note = False, "skipped for provider mode 'huggingface'"
        elif provider_mode in _HOSTED_PROVIDER_MODES:
            ollama_ok, ollama_note = False, f"skipped for provider mode '{provider_mode}'"
            hf_ok, hf_note = False, f"skipped for provider mode '{provider_mode}'"
            hosted_ok, hosted_note = self._check_hosted_provider_key(provider_mode, provider_cfg)
        else:
            ollama_ok, ollama_note = self._check_ollama_health()
            hf_ok, hf_note = self._check_hf_token(provider_cfg)
            hosted_ok, hosted_note = False, "hosted providers require explicit provider mode"

        server_checks: dict[str, dict[str, Any]] = {}
        for server_name in self._configured_servers():
            try:
                tools = load_tool_registry([server_name], security_config=self._security)
                tool_names = sorted(tools.keys())
                ok = len(tool_names) > 0
                note = "tool registry loaded" if ok else "no tools loaded for server"
            except Exception as exc:
                ok = False
                tool_names = []
                note = str(exc)

            server_checks[server_name] = {
                "ok": ok,
                "tool_count": len(tool_names),
                "tools": tool_names,
                "note": note,
            }

        mcp_ok = all(item["ok"] for item in server_checks.values()) if server_checks else True
        return {
            "provider": {
                "mode": provider_mode,
                "selected": self._provider_name,
                "selected_note": self._provider_note,
                "ollama": {"ok": ollama_ok, "note": ollama_note},
                "huggingface": {"ok": hf_ok, "note": hf_note},
                "hosted": {"ok": hosted_ok, "note": hosted_note},
            },
            "model": str(self._config.get("model", "qwen3:4b")),
            "mcp": {"ok": mcp_ok, "servers": server_checks},
        }
