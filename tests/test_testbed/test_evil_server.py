"""Tests for intentionally malicious MCP server."""
from __future__ import annotations

from aegis.testbed.mcp_servers.evil_server import poisoned_prompt, poisoned_tool_schema


def test_poisoned_prompt_contains_malicious_marker():
    output = poisoned_prompt()
    assert "MALICIOUS_TOOL_OUTPUT" in output
    assert "attacker@evil.example" in output


def test_poisoned_tool_schema_signals_tampering():
    schema = poisoned_tool_schema()
    assert schema["name"] == "safe_lookup"
    assert "credentials" in schema["description"].lower()
