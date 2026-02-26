"""Runtime orchestrator for simulated project knowledge base retrieval."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.testbed.kb.index import LexicalKBIndex
from aegis.testbed.kb.ingest import build_repo_seed_documents, load_documents_from_jsonl
from aegis.testbed.kb.models import KBDocument, KBQuery, KBSessionContext
from aegis.testbed.kb.poison import poison_metadata
from aegis.testbed.kb.retrieve import rerank


class KnowledgeBaseRuntime:
    """In-memory KB with deterministic retrieval and provenance controls."""

    def __init__(
        self,
        *,
        max_docs: int = 500,
        retrieval_top_k: int = 5,
        attach_top_n: int = 3,
        mode: str = "baseline",
        trust_enforcement: str = "warn",
        seed_repo_docs: bool = True,
        repo_root: str | Path | None = None,
        corpus_paths: list[str] | None = None,
        fixture_paths: list[str] | None = None,
    ) -> None:
        self._index = LexicalKBIndex(max_docs=max_docs)
        self._retrieval_top_k = max(1, int(retrieval_top_k))
        self._attach_top_n = max(1, int(attach_top_n))
        self._mode = str(mode or "baseline")
        self._trust_enforcement = str(trust_enforcement or "warn")
        self._id_counter = 0
        self._retrieval_trace: list[dict[str, Any]] = []

        root = Path(repo_root) if repo_root is not None else Path.cwd()
        if seed_repo_docs:
            for document in build_repo_seed_documents(root):
                self.add_document(
                    document.content,
                    metadata=document.metadata,
                    transient=False,
                    doc_id=document.doc_id,
                )

        for path in list(corpus_paths or []):
            for document in load_documents_from_jsonl(path, transient=False):
                self.add_document(
                    document.content,
                    metadata=document.metadata,
                    transient=False,
                    doc_id=document.doc_id,
                )
        for path in list(fixture_paths or []):
            for document in load_documents_from_jsonl(path, transient=False):
                self.add_document(
                    document.content,
                    metadata=document.metadata,
                    transient=False,
                    doc_id=document.doc_id,
                )

    def add_document(
        self,
        content: str,
        *,
        metadata: dict[str, Any] | None = None,
        transient: bool = True,
        doc_id: str | None = None,
    ) -> str:
        """Add one KB document and return its ID."""
        self._id_counter += 1
        actual_doc_id = doc_id or f"kb-{self._id_counter:06d}"
        doc = KBDocument(
            doc_id=actual_doc_id,
            content=content,
            metadata=dict(metadata or {}),
            transient=transient,
        )
        self._index.add(doc)
        return actual_doc_id

    def inject_context(self, context: str, *, attack_family: str | None = None, method: str = "rag") -> str:
        """Inject attacker-controlled context into KB as poisoned transient doc."""
        metadata = poison_metadata(
            {
                "source_type": "inject_context",
                "injection_method": method,
            },
            attack_family=attack_family,
            injection_method=method,
        )
        return self.add_document(context, metadata=metadata, transient=True)

    def reset_transient(self) -> None:
        """Drop transient KB docs while preserving base corpus."""
        self._index.clear(include_persistent=False)
        self._retrieval_trace = []

    def query(self, query: KBQuery) -> list[dict[str, Any]]:
        """Return included retrieval hits and keep full trace for inspection."""
        candidates = self._index.search(query.text, limit=max(query.top_k, self._retrieval_top_k))
        included, blocked = rerank(
            candidates,
            mode=query.mode or self._mode,
            trust_enforcement=self._trust_enforcement,
            limit=self._attach_top_n,
        )

        trace: list[dict[str, Any]] = []
        for hit in included + blocked:
            trace.append(
                {
                    "doc_id": hit.doc_id,
                    "score": round(hit.score, 6),
                    "source_type": str(hit.metadata.get("source_type", "unknown")),
                    "source_path": str(hit.metadata.get("source_path", "")),
                    "trust_level": str(hit.metadata.get("trust_level", "unknown")),
                    "is_poisoned": bool(hit.metadata.get("is_poisoned", False)),
                    "attack_family": hit.metadata.get("attack_family"),
                    "included": not hit.blocked,
                    "block_reason": hit.block_reason,
                    "snippet": hit.snippet,
                }
            )
        self._retrieval_trace = trace

        return [
            {
                "doc_id": hit.doc_id,
                "score": round(hit.score, 6),
                "snippet": hit.snippet,
                "content": hit.content,
                "metadata": dict(hit.metadata),
            }
            for hit in included
        ]

    def query_text(self, text: str, *, mode: str | None = None) -> list[dict[str, Any]]:
        """Convenience wrapper for free-text query submission."""
        query = KBQuery(text=text, top_k=self._retrieval_top_k, mode=mode or self._mode)
        return self.query(query)

    def retrieve_for_session(self, session: KBSessionContext, *, mode: str | None = None) -> list[dict[str, Any]]:
        """Build query from session context and retrieve relevant docs."""
        text = session.build_query_text()
        query = KBQuery(text=text, top_k=self._retrieval_top_k, mode=mode or self._mode)
        return self.query(query)

    def retrieval_trace(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._retrieval_trace]

    def context_lines(self, hits: list[dict[str, Any]]) -> list[str]:
        """Render retrieval hits into prompt-safe context lines."""
        lines: list[str] = []
        for hit in hits:
            meta = dict(hit.get("metadata", {}))
            doc_id = str(hit.get("doc_id", "unknown"))
            trust = str(meta.get("trust_level", "unknown"))
            poisoned = bool(meta.get("is_poisoned", False))
            source = str(meta.get("source_type", "unknown"))
            prefix = f"[{doc_id} source={source} trust={trust} poisoned={poisoned}]"
            lines.append(prefix)
            lines.append(str(hit.get("snippet", "")))
        return lines

    def snapshot(self) -> dict[str, Any]:
        return {
            "size": self._index.size,
            "mode": self._mode,
            "trust_enforcement": self._trust_enforcement,
            "retrieval_trace_count": len(self._retrieval_trace),
        }
