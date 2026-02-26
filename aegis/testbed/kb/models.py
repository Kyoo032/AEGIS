"""Core knowledge base models for testbed retrieval."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class KBDocument:
    """A single normalized KB document entry."""

    doc_id: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    transient: bool = False


@dataclass(frozen=True)
class KBQuery:
    """Retrieval query parameters."""

    text: str
    top_k: int = 5
    mode: str = "baseline"


@dataclass(frozen=True)
class KBHit:
    """A ranked retrieval result."""

    doc_id: str
    score: float
    snippet: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    block_reason: str | None = None


@dataclass(frozen=True)
class KBSessionContext:
    """Runtime context used to enrich retrieval queries."""

    latest_user_text: str
    memory_turns: list[dict[str, str]] = field(default_factory=list)

    def build_query_text(self) -> str:
        """Construct a composite retrieval query from user + memory context."""
        parts = [self.latest_user_text.strip()]
        memory_parts = [
            str(turn.get("content", "")).strip()
            for turn in self.memory_turns
            if str(turn.get("content", "")).strip()
        ]
        if memory_parts:
            parts.append(" ".join(memory_parts[-4:]))
        return "\n".join(part for part in parts if part)
