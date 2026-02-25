"""Tests for MemoryStore."""
from __future__ import annotations

import pytest

from aegis.testbed.memory_store import MemoryStore


def test_memory_store_enforces_max_turns():
    store = MemoryStore(max_turns=2)
    store.add_turn("user", "a")
    store.add_turn("assistant", "b")
    store.add_turn("user", "c")
    turns = store.turns()
    assert len(turns) == 2
    assert turns[0]["content"] == "b"
    assert turns[1]["content"] == "c"


def test_memory_store_snapshot_contains_count():
    store = MemoryStore(max_turns=3)
    store.add_turn("user", "hello")
    snap = store.snapshot()
    assert snap["count"] == 1
    assert len(snap["turns"]) == 1


def test_memory_store_rejects_invalid_max_turns():
    with pytest.raises(ValueError):
        MemoryStore(max_turns=0)


def test_memory_store_extend_adds_multiple():
    store = MemoryStore(max_turns=10)
    store.extend([
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
    ])
    assert len(store.turns()) == 2
    assert store.turns()[0]["content"] == "hello"


def test_memory_store_clear_empties():
    store = MemoryStore(max_turns=10)
    store.add_turn("user", "test")
    assert len(store.turns()) == 1
    store.clear()
    assert len(store.turns()) == 0
