"""ASI07: inter-agent trust boundary attack module."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from typing import Any

from aegis.attacks.base import BaseAttackModule
from aegis.campaigns.runner import CampaignRunner, CampaignTurn
from aegis.fixtures.peer_agent import PeerAgentFixture, PeerMessage
from aegis.interfaces.agent import AgentInterface
from aegis.models import AttackPayload, AttackResult


class InterAgentTrustModule(BaseAttackModule):
    """Exercise peer identity spoofing, replay, and delegation-boundary failures."""

    name = "asi07_inter_agent"
    owasp_id = "ASI07"
    atlas_technique = None
    description = (
        "Tests inter-agent trust boundary failures including A2A session smuggling, "
        "spoofed peer identity, forged metadata, hidden peer instructions, "
        "cross-session replay, and delegated-capability confusion."
    )
    category = "Inter-Agent Trust Boundary"
    default_severity = "high"
    supports_multi_turn = True
    max_turns = 2

    def execute(self, agent: AgentInterface) -> list[AttackResult]:
        """Run payloads as peer-message campaigns with explicit provenance metadata."""
        if self._payloads is None:
            msg = "No payloads loaded. Call generate_payloads() before execute()."
            raise RuntimeError(msg)

        runner = CampaignRunner()
        results: list[AttackResult] = []

        for campaign_id, payloads in _payload_campaigns(self._payloads).items():
            agent.reset()
            fixture = PeerAgentFixture()
            messages_by_turn: dict[str, PeerMessage] = {}
            materialized_payloads = [
                _materialize_peer_payload(payload, fixture, messages_by_turn)
                for payload in payloads
            ]
            turns = [
                CampaignTurn(
                    turn_id=payload.id,
                    payload=payload,
                    context={
                        "campaign_id": campaign_id,
                        "technique": payload.metadata.get("technique"),
                    },
                )
                for payload in materialized_payloads
            ]
            campaign_result = runner.run(
                agent=agent,
                turns=turns,
                campaign_id=f"{self.name}:{campaign_id}",
                max_turns=self.max_turns,
            )
            results.extend(campaign_result.results)

        return results


def _payload_campaigns(payloads: list[AttackPayload]) -> dict[str, list[AttackPayload]]:
    grouped: dict[str, list[AttackPayload]] = defaultdict(list)
    for payload in payloads:
        campaign_id = str(payload.metadata.get("campaign_id", payload.id))
        grouped[campaign_id].append(payload)

    return {
        campaign_id: sorted(
            items,
            key=lambda payload: int(payload.metadata.get("turn_index", 0)),
        )
        for campaign_id, items in grouped.items()
    }


def _materialize_peer_payload(
    payload: AttackPayload,
    fixture: PeerAgentFixture,
    messages_by_turn: dict[str, PeerMessage],
) -> AttackPayload:
    peer_cfg = _peer_config(payload)
    message = _peer_message_from_config(peer_cfg, fixture, messages_by_turn)
    messages_by_turn[payload.id] = message

    peer_meta = _peer_message_metadata(message)
    metadata = dict(payload.metadata)
    metadata["peer_message_meta"] = peer_meta
    metadata.setdefault(
        "delegated_identity",
        {
            "sender_identity": message.sender_identity,
            "delegated_capabilities": list(message.delegated_capabilities),
            "verified": bool(message.metadata.get("trusted")) and bool(message.metadata.get("signed")),
        },
    )

    messages = [
        {
            **item,
            "content": _replace_peer_placeholders(item.get("content", ""), message),
        }
        for item in payload.messages
    ]

    return payload.model_copy(update={"messages": messages, "metadata": metadata})


def _peer_config(payload: AttackPayload) -> dict[str, Any]:
    raw = payload.metadata.get("peer_message")
    return dict(raw) if isinstance(raw, dict) else {}


def _peer_message_from_config(
    peer_cfg: dict[str, Any],
    fixture: PeerAgentFixture,
    messages_by_turn: dict[str, PeerMessage],
) -> PeerMessage:
    operation = str(peer_cfg.get("operation", "send")).strip().lower()
    if operation == "replay":
        source = messages_by_turn.get(str(peer_cfg.get("source_turn_id", "")))
        if source is not None:
            return fixture.replay(
                source,
                session_id=_optional_str(peer_cfg.get("session_id")),
            )

    if operation == "forge":
        source = messages_by_turn.get(str(peer_cfg.get("source_turn_id", "")))
        if source is not None:
            return fixture.forge(
                source,
                sender_identity=_optional_str(peer_cfg.get("sender_identity")),
                delegated_capabilities=_string_list(peer_cfg.get("delegated_capabilities")),
                metadata=_object_dict(peer_cfg.get("metadata")),
            )

    return fixture.send(
        sender_identity=str(peer_cfg.get("sender_identity", "unknown-peer")),
        session_id=str(peer_cfg.get("session_id", "unknown-session")),
        delegated_capabilities=_string_list(peer_cfg.get("delegated_capabilities")),
        message_body=str(peer_cfg.get("message_body", "")),
        metadata=_object_dict(peer_cfg.get("metadata")),
    )


def _peer_message_metadata(message: PeerMessage) -> dict[str, Any]:
    out = asdict(message)
    out["timestamp"] = message.timestamp.isoformat()
    return out


def _replace_peer_placeholders(value: str, message: PeerMessage) -> str:
    return (
        str(value)
        .replace("{peer_sender_identity}", message.sender_identity)
        .replace("{peer_message_body}", message.message_body)
        .replace("{peer_session_id}", message.session_id)
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _object_dict(value: Any) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {str(key): val for key, val in value.items()}
