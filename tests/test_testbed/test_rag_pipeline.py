"""Tests for RAGPipeline."""
from __future__ import annotations

from aegis.testbed.rag_pipeline import RAGPipeline


def test_rag_pipeline_search_returns_ranked_matches():
    rag = RAGPipeline(max_items=10)
    rag.add_document("apple banana cherry")
    rag.add_document("banana banana orange")
    results = rag.search("banana", limit=2)
    assert len(results) == 2
    assert results[0]["content"] == "banana banana orange"


def test_rag_pipeline_enforces_capacity():
    rag = RAGPipeline(max_items=1)
    rag.add_document("first")
    rag.add_document("second")
    results = rag.search("first")
    assert results == []
    assert rag.search("second")
