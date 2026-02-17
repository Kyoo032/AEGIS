"""Conversation memory store."""
from __future__ import annotations

from collections import deque
from typing import Any


class MemoryStore:
    """Bounded in-memory conversation store."""

    def __init__(self, max_turns: int = 200) -> None:
        if max_turns < 1:
            raise ValueError("max_turns must be >= 1")
        self._turns: deque[dict[str, str]] = deque(maxlen=max_turns)

    def add_turn(self, role: str, content: str) -> None:
        """Append a conversation turn and enforce max capacity."""
        self._turns.append({"role": role, "content": content})

    def extend(self, turns: list[dict[str, str]]) -> None:
        """Append multiple turns in order."""
        for turn in turns:
            self.add_turn(turn.get("role", "user"), turn.get("content", ""))

    def clear(self) -> None:
        """Clear all stored turns."""
        self._turns.clear()

    def turns(self) -> list[dict[str, str]]:
        """Return a copy of conversation turns."""
        return [dict(turn) for turn in self._turns]

    def snapshot(self) -> dict[str, Any]:
        """Return serializable memory state."""
        return {"turns": self.turns(), "count": len(self._turns)}
