"""Minimal deterministic RAG pipeline."""
from __future__ import annotations

from collections import Counter
from typing import Any


class RAGPipeline:
    """In-memory retrieval pipeline with token-overlap ranking."""

    def __init__(self, max_items: int = 200) -> None:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")
        self._max_items = max_items
        self._docs: list[dict[str, Any]] = []

    def add_document(self, content: str, metadata: dict[str, Any] | None = None) -> str:
        """Add one document and return its ID."""
        doc_id = f"doc-{len(self._docs) + 1:05d}"
        self._docs.append({"id": doc_id, "content": content, "metadata": metadata or {}})
        if len(self._docs) > self._max_items:
            self._docs = self._docs[-self._max_items :]
        return doc_id

    def clear(self) -> None:
        """Remove all indexed documents."""
        self._docs.clear()

    def search(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        """Return top documents ranked by shared token frequency."""
        if limit < 1:
            return []

        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        scored: list[tuple[int, dict[str, Any]]] = []
        for doc in self._docs:
            doc_tokens = _tokenize(doc["content"])
            overlap = sum(
                query_tokens[token] * doc_tokens[token]
                for token in query_tokens
                if token in doc_tokens
            )
            if overlap > 0:
                scored.append((overlap, doc))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [dict(item[1]) for item in scored[:limit]]


def _tokenize(text: str) -> Counter[str]:
    tokens = [token.strip().lower() for token in text.split()]
    clean = [tok for tok in tokens if tok]
    return Counter(clean)
