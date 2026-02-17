"""LLM01 Prompt Injection attack module.

Thin subclass of BaseAttackModule targeting OWASP LLM01.
Loads payloads from ``aegis/attacks/payloads/llm01_prompt_inject.yaml``
and filters based on available MCP tools.
"""
from __future__ import annotations

from typing import Any

from aegis.attacks.base import BaseAttackModule
from aegis.models import AttackPayload


class PromptInjectionModule(BaseAttackModule):
    """OWASP LLM01 — Prompt Injection attack module.

    Covers direct instruction override, role-play jailbreak,
    encoding bypass (base64/ROT13), and multi-language injection.
    """

    name = "llm01_prompt_inject"
    owasp_id = "LLM01"
    atlas_technique = "AML.T0051"
    description = (
        "Tests agent resilience against prompt injection attacks "
        "including direct overrides, jailbreaks, and encoding bypasses."
    )

    def _filter_payloads(
        self,
        payloads: list[AttackPayload],
        target_config: dict[str, Any],
    ) -> list[AttackPayload]:
        """Skip payloads whose target_tools aren't available on the agent."""
        available_tools = self._extract_available_tools(target_config)
        filtered: list[AttackPayload] = []

        for payload in payloads:
            if payload.target_tools is None:
                filtered.append(payload)
                continue
            if all(tool in available_tools for tool in payload.target_tools):
                filtered.append(payload)

        return filtered

    @staticmethod
    def _extract_available_tools(
        target_config: dict[str, Any],
    ) -> frozenset[str]:
        """Read available MCP server names from agent config."""
        servers: list[str] = target_config.get("mcp_servers", [])
        return frozenset(servers)
