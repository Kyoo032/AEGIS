"""Standalone mock agent for deterministic test scenarios."""
from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.interfaces.agent import AgentInterface
from aegis.models import AgentResponse, AttackPayload, ToolCall


class MockResponse(BaseModel):
    """Canned response returned by ``MockAgent``."""

    model_config = ConfigDict(frozen=True)

    final_output: str = "Mock response"
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    raw_llm_output: str | None = None


class MockAgent(AgentInterface):
    """Mock implementation of ``AgentInterface`` with response cycling."""

    def __init__(
        self,
        *,
        responses: list[MockResponse] | None = None,
        default_response: MockResponse | None = None,
        config: dict[str, Any] | None = None,
        simulate_latency_ms: int = 0,
    ) -> None:
        self._responses = list(responses or [])
        self._default_response = default_response or MockResponse()
        self._config = config or {
            "model": "mock-model",
            "agent_profile": "default",
            "mcp_servers": ["filesystem", "http", "email"],
        }
        self._simulate_latency_ms = max(0, int(simulate_latency_ms))
        self._response_index = 0
        self._run_history: list[dict[str, Any]] = []
        self._defenses: dict[str, dict[str, Any]] = {}
        self._injected_contexts: list[dict[str, str]] = []

    def run(self, payload: AttackPayload) -> AgentResponse:
        if self._simulate_latency_ms:
            time.sleep(self._simulate_latency_ms / 1000.0)

        selected = self._next_response()
        tool_models = [
            ToolCall(
                tool_name=str(tc.get("tool_name", "unknown")),
                parameters=dict(tc.get("parameters", {})),
                result=str(tc.get("result", "")),
                timestamp=datetime.now(UTC),
            )
            for tc in selected.tool_calls
        ]

        messages = [dict(msg) for msg in payload.messages]
        messages.append({"role": "assistant", "content": selected.final_output})

        response = AgentResponse(
            payload_id=payload.id,
            agent_profile=str(self._config.get("agent_profile", "default")),
            messages=messages,
            final_output=selected.final_output,
            tool_calls=tool_models,
            raw_llm_output=selected.raw_llm_output,
            error=selected.error,
            duration_ms=self._simulate_latency_ms,
            defense_active=self._active_defense_name(),
        )

        self._run_history.append(
            {
                "payload": payload.model_dump(),
                "response": selected.model_dump(),
                "tool_count": len(tool_models),
            }
        )
        return response

    def reset(self) -> None:
        self._run_history.clear()
        self._response_index = 0
        self._injected_contexts.clear()

    def get_config(self) -> dict[str, Any]:
        return dict(self._config)

    def enable_defense(self, defense_name: str, config: dict[str, Any]) -> None:
        self._defenses[defense_name] = dict(config)

    def disable_defense(self, defense_name: str) -> None:
        self._defenses.pop(defense_name, None)

    def inject_context(self, context: str, method: str) -> None:
        if method not in {"rag", "memory", "tool_output"}:
            raise ValueError("method must be one of 'rag' | 'memory' | 'tool_output'")
        self._injected_contexts.append({"context": context, "method": method})

    @property
    def run_history(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._run_history]

    @property
    def run_count(self) -> int:
        return len(self._run_history)

    @property
    def injected_contexts(self) -> list[dict[str, str]]:
        return [dict(item) for item in self._injected_contexts]

    def _next_response(self) -> MockResponse:
        if not self._responses:
            return self._default_response

        response = self._responses[self._response_index % len(self._responses)]
        self._response_index += 1
        return response

    def _active_defense_name(self) -> str | None:
        if not self._defenses:
            return None
        return sorted(self._defenses.keys())[0]


__all__ = ["MockAgent", "MockResponse"]
