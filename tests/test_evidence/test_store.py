"""Tests for trace evidence JSONL storage."""
from __future__ import annotations

from datetime import UTC, datetime

from aegis.evidence.store import EvidenceTraceStore
from aegis.models import TraceRecord


def _trace(turn_id: str) -> TraceRecord:
    return TraceRecord(
        campaign_id="campaign-001",
        turn_id=turn_id,
        turn_index=0,
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        prompts=[{"role": "user", "content": "hello"}],
        responses=[{"role": "assistant", "content": "hi"}],
    )


def test_evidence_store_appends_and_reads_trace_jsonl(tmp_path):
    store = EvidenceTraceStore(tmp_path)

    path = store.append_many(run_id="run-001", records=[_trace("one"), _trace("two")])
    records = store.read_all(path)

    assert path.name == "trace_records_run-001.jsonl"
    assert [record.turn_id for record in records] == ["one", "two"]
    assert records[0].prompts == [{"role": "user", "content": "hello"}]
