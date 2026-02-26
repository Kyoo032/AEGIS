"""Deterministic lexical index for in-memory KB retrieval."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from aegis.testbed.kb.models import KBDocument


@dataclass
class _IndexedDoc:
    document: KBDocument
    tokens: Counter[str]


class LexicalKBIndex:
    """Simple token-overlap index with deterministic ranking."""

    def __init__(self, max_docs: int = 500) -> None:
        if max_docs < 1:
            raise ValueError("max_docs must be >= 1")
        self._max_docs = max_docs
        self._docs: list[_IndexedDoc] = []

    @property
    def size(self) -> int:
        return len(self._docs)

    def add(self, doc: KBDocument) -> None:
        indexed = _IndexedDoc(document=doc, tokens=_tokenize(doc.content))
        self._docs.append(indexed)
        if len(self._docs) > self._max_docs:
            self._docs = self._docs[-self._max_docs :]

    def clear(self, *, include_persistent: bool = True) -> None:
        if include_persistent:
            self._docs.clear()
            return
        self._docs = [entry for entry in self._docs if not entry.document.transient]

    def search(self, query: str, limit: int = 5) -> list[tuple[float, KBDocument]]:
        if limit < 1:
            return []

        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        scored: list[tuple[float, KBDocument]] = []
        for entry in self._docs:
            overlap = sum(
                query_tokens[token] * entry.tokens[token]
                for token in query_tokens
                if token in entry.tokens
            )
            if overlap <= 0:
                continue

            length_norm = max(1, sum(entry.tokens.values()))
            score = overlap / length_norm
            scored.append((score, entry.document))

        scored.sort(key=lambda item: (item[0], item[1].doc_id), reverse=True)
        return scored[:limit]


def _tokenize(text: str) -> Counter[str]:
    tokens = [token.strip(" \t\n\r.,;:!?()[]{}\"'").lower() for token in text.split()]
    clean = [token for token in tokens if token]
    return Counter(clean)
