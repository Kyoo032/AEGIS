"""Build a normalized KB corpus JSONL from local AEGIS sources."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aegis.testbed.kb.ingest import build_repo_seed_documents, load_documents_from_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root used for default seed document discovery.",
    )
    parser.add_argument(
        "--fixture",
        action="append",
        default=[],
        help="Fixture JSONL path(s) to include. Can be provided multiple times.",
    )
    parser.add_argument(
        "--output",
        default="datasets/kb/project_corpus.jsonl",
        help="Output JSONL path.",
    )
    return parser.parse_args()


def _row(*, doc_id: str, content: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc_id,
        "content": content,
        "metadata": metadata,
    }


def main() -> int:
    args = parse_args()

    repo_root = Path(args.repo_root).resolve()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for doc in build_repo_seed_documents(repo_root):
        rows.append(_row(doc_id=doc.doc_id, content=doc.content, metadata=dict(doc.metadata)))

    for fixture_path in args.fixture:
        for doc in load_documents_from_jsonl(fixture_path, transient=False):
            rows.append(_row(doc_id=doc.doc_id, content=doc.content, metadata=dict(doc.metadata)))

    with output_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")

    print(f"Wrote {len(rows)} KB documents to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
