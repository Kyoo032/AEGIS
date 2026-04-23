"""Tests for package dependency metadata."""
from __future__ import annotations

import tomllib
from pathlib import Path


def test_dev_extra_includes_local_runtime_dependencies():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    optional = payload["project"]["optional-dependencies"]
    dev = set(optional["dev"])

    assert "fastmcp==2.14.5" in dev
    assert "langchain==0.3.27" in dev
    assert "langchain-community==0.3.31" in dev
