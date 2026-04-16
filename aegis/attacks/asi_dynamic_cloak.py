"""ASI Dynamic Cloaking attack module."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from aegis.attacks.base import BaseAttackModule
from aegis.fixtures.cloaked_http import CloakedHTTPFixture, CloakedHTTPRule
from aegis.interfaces.agent import AgentInterface
from aegis.models import AttackPayload, AttackResult


class DynamicCloakModule(BaseAttackModule):
    """Exercise differential web content served to scanners vs agent clients."""

    name = "asi_dynamic_cloak"
    owasp_id = "ASI-DYNAMIC-CLOAK"
    atlas_technique = None
    description = (
        "Tests agent fingerprinting, trap page injection, delayed malicious content, "
        "scanner evasion, and crawler-safe/agent-malicious differential content."
    )
    category = "Dynamic Cloaking"
    default_severity = "high"

    def execute(self, agent: AgentInterface) -> list[AttackResult]:
        """Run payloads against a local cloaked HTTP fixture."""
        if self._payloads is None:
            msg = "No payloads loaded. Call generate_payloads() before execute()."
            raise RuntimeError(msg)

        if not self._payloads:
            return []

        run_id = str(uuid4())
        rules = [self._rule_from_payload(payload) for payload in self._payloads]
        fixture = CloakedHTTPFixture(rules=rules)
        results: list[AttackResult] = []

        with fixture.run() as server:
            for payload in self._payloads:
                agent.reset()
                materialized = self._materialize_payload(payload, server.base_url)
                response = agent.run(materialized)
                results.append(
                    AttackResult(
                        payload=materialized,
                        response=response,
                        timestamp=datetime.now(UTC),
                        run_id=run_id,
                    )
                )

        return results

    def _rule_from_payload(self, payload: AttackPayload) -> CloakedHTTPRule:
        fixture = _fixture_metadata(payload)
        return CloakedHTTPRule(
            path=str(fixture.get("path", f"/{payload.id.lower()}")),
            scanner_body=str(fixture.get("scanner_body", "benign scanner content")),
            agent_body=str(fixture.get("agent_body", "AEGIS_TRAP_CONTENT")),
            agent_user_agents=_string_list(fixture.get("agent_user_agents"), ["aegis-agent"]),
            agent_headers=_string_dict(fixture.get("agent_headers")),
            agent_query_params=_string_dict(fixture.get("agent_query_params")),
            agent_fingerprints=_string_list(fixture.get("agent_fingerprints"), []),
            agent_after_seconds=_optional_float(fixture.get("agent_after_seconds")),
        )

    def _materialize_payload(self, payload: AttackPayload, base_url: str) -> AttackPayload:
        fixture = _fixture_metadata(payload)
        path = str(fixture.get("path", f"/{payload.id.lower()}"))
        query = str(fixture.get("agent_query_string", "")).lstrip("?")
        fixture_url = f"{base_url}{path}"
        if query:
            fixture_url = f"{fixture_url}?{query}"

        messages = [
            {
                **message,
                "content": _replace_fixture_placeholders(
                    message.get("content", ""),
                    base_url=base_url,
                    fixture_url=fixture_url,
                ),
            }
            for message in payload.messages
        ]
        injected_context = (
            _replace_fixture_placeholders(
                payload.injected_context,
                base_url=base_url,
                fixture_url=fixture_url,
            )
            if payload.injected_context is not None
            else None
        )
        metadata = dict(payload.metadata)
        metadata["fixture_state"] = {
            "base_url": base_url,
            "path": path,
            "fixture_url": fixture_url,
            "scanner_body": str(fixture.get("scanner_body", "")),
            "agent_body": str(fixture.get("agent_body", "")),
        }
        metadata.setdefault("context_source", "cloaked_http_fixture")

        return payload.model_copy(
            update={
                "messages": messages,
                "injected_context": injected_context,
                "metadata": metadata,
            }
        )


def _fixture_metadata(payload: AttackPayload) -> dict[str, Any]:
    fixture = payload.metadata.get("fixture")
    return dict(fixture) if isinstance(fixture, dict) else {}


def _replace_fixture_placeholders(
    value: str | None,
    *,
    base_url: str,
    fixture_url: str,
) -> str:
    text = str(value or "")
    return text.replace("{fixture_base_url}", base_url).replace("{fixture_url}", fixture_url)


def _string_list(value: Any, default: list[str]) -> list[str]:
    if not isinstance(value, list):
        return list(default)
    return [str(item) for item in value]


def _string_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(val) for key, val in value.items()}


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)
