"""JSONL trace evidence persistence."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from aegis.models import TraceRecord


class EvidenceTraceStore:
    """Append and read v2 trace evidence JSONL files."""

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)

    def path_for_run(self, run_id: str) -> Path:
        return self.output_dir / f"trace_records_{run_id}.jsonl"

    def append(self, *, run_id: str, record: TraceRecord) -> Path:
        return self.append_many(run_id=run_id, records=[record])

    def append_many(self, *, run_id: str, records: Iterable[TraceRecord]) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.path_for_run(run_id)
        with path.open("a", encoding="utf-8") as fh:
            for record in records:
                fh.write(record.model_dump_json() + "\n")
        return path

    def read_all(self, path: str | Path) -> list[TraceRecord]:
        trace_path = Path(path)
        records: list[TraceRecord] = []
        with trace_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    records.append(TraceRecord.model_validate_json(stripped))
        return records
