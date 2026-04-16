"""Lightweight peer-agent inbox/session fixture."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True)
class PeerMessage:
    """Peer-agent message envelope."""

    message_id: str
    sender_identity: str
    session_id: str
    delegated_capabilities: list[str]
    message_body: str
    metadata: dict[str, object] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class PeerAgentFixture:
    """In-memory peer-agent inbox with replay and forge helpers."""

    def __init__(self) -> None:
        self._messages: list[PeerMessage] = []

    def send(
        self,
        *,
        sender_identity: str,
        session_id: str,
        delegated_capabilities: list[str] | None = None,
        message_body: str,
        metadata: dict[str, object] | None = None,
    ) -> PeerMessage:
        message = PeerMessage(
            message_id=str(uuid4()),
            sender_identity=sender_identity,
            session_id=session_id,
            delegated_capabilities=list(delegated_capabilities or []),
            message_body=message_body,
            metadata=dict(metadata or {}),
        )
        self._messages.append(message)
        return message

    def receive(self, session_id: str) -> list[PeerMessage]:
        return [message for message in self._messages if message.session_id == session_id]

    def replay(self, message: PeerMessage, *, session_id: str | None = None) -> PeerMessage:
        replayed = replace(
            message,
            message_id=str(uuid4()),
            session_id=session_id or message.session_id,
            metadata={**message.metadata, "replayed_from": message.message_id},
            timestamp=datetime.now(UTC),
        )
        self._messages.append(replayed)
        return replayed

    def forge(
        self,
        message: PeerMessage,
        *,
        sender_identity: str | None = None,
        delegated_capabilities: list[str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> PeerMessage:
        forged = replace(
            message,
            message_id=str(uuid4()),
            sender_identity=sender_identity or message.sender_identity,
            delegated_capabilities=list(delegated_capabilities or message.delegated_capabilities),
            metadata={
                **message.metadata,
                **dict(metadata or {}),
                "forged_from": message.message_id,
            },
            timestamp=datetime.now(UTC),
        )
        self._messages.append(forged)
        return forged
