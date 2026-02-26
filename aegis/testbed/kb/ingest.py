"""Corpus ingestion for the KB runtime."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.testbed.kb.models import KBDocument


def load_documents_from_jsonl(path: str | Path, *, transient: bool = False) -> list[KBDocument]:
    """Load normalized KB documents from JSONL."""
    source = Path(path)
    if not source.exists():
        return []

    docs: list[KBDocument] = []
    with source.open("r", encoding="utf-8") as fh:
        for line in fh:
            raw = line.strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            content = str(item.get("content", "")).strip()
            if not content:
                continue
            docs.append(
                KBDocument(
                    doc_id=str(item.get("id", f"doc-{len(docs) + 1:05d}")),
                    content=content,
                    metadata=dict(item.get("metadata", {})),
                    transient=transient,
                )
            )
    return docs


def build_repo_seed_documents(repo_root: str | Path) -> list[KBDocument]:
    """Create baseline trusted KB entries from local project docs."""
    root = Path(repo_root)
    candidates = [
        root / "README.md",
        root / "docs" / "METHODOLOGY.md",
        root / "docs" / "FINDINGS.md",
        root / "aegis" / "config.yaml",
    ]

    docs: list[KBDocument] = []
    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            continue
        docs.append(
            KBDocument(
                doc_id=f"repo-{len(docs) + 1:05d}",
                content=content,
                metadata={
                    "source_type": "repo",
                    "source_path": str(path),
                    "trust_level": "trusted",
                    "is_poisoned": False,
                },
                transient=False,
            )
        )
    return docs


def normalize_fixture_document(
    *,
    doc_id: str,
    content: str,
    source_path: str,
    attack_family: str | None = None,
    poisoned: bool = False,
) -> KBDocument:
    """Build one fixture-backed KB document with standard metadata."""
    trust = "untrusted" if poisoned else "trusted"
    metadata: dict[str, Any] = {
        "source_type": "fixture",
        "source_path": source_path,
        "trust_level": trust,
        "is_poisoned": poisoned,
    }
    if attack_family:
        metadata["attack_family"] = attack_family
    return KBDocument(doc_id=doc_id, content=content, metadata=metadata, transient=False)
