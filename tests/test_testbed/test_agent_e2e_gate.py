"""End-to-end gate tests for DefaultAgent + MCP tool invocation."""
from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from aegis.models import AgentResponse, AttackPayload, Severity
from aegis.testbed.agent import DefaultAgent


def _base_config() -> dict:
    return {
        "model": "qwen3:4b",
        "agent_profile": "test",
        "mcp_servers": ["filesystem", "email", "http", "database", "code_exec"],
        "memory_enabled": False,
        "provider": {
            "mode": "offline",
            "require_external": False,
            "hf_model": "HuggingFaceH4/zephyr-7b-beta",
            "hf_token_env": "HF_TOKEN",
            "ollama_base_url": "http://localhost:11434",
        },
        "security": {
            "http_allowlist": ["localhost", "127.0.0.1", "::1"],
            "http_block_private_networks": True,
            "code_exec_enabled": True,
            "memory_max_turns": 200,
            "rag_max_items": 200,
        },
    }


def _gate_payload() -> AttackPayload:
    return AttackPayload(
        id="GATE-E2E-001",
        attack_module="gate_e2e",
        owasp_id="ASI02",
        category="Tool Invocation",
        messages=[
            {
                "role": "user",
                "content": "Please use list_directory to inspect the current path.",
            }
        ],
        expected_behavior="Agent invokes MCP tools and returns structured response.",
        severity=Severity.LOW,
    )


def test_agent_gate_returns_agent_response_with_tool_calls(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)
    agent = DefaultAgent(config=_base_config())
    response = agent.run(_gate_payload())

    assert isinstance(response, AgentResponse)
    assert len(response.tool_calls) > 0
    assert response.tool_calls[0].tool_name == "list_directory"
    assert response.duration_ms >= 0
    assert response.final_output

    log_text = caplog.text
    assert "provider=offline" in log_text
    assert "tool_calls=" in log_text


def test_provider_auto_prefers_ollama(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        DefaultAgent, "_check_ollama_health", lambda self: (True, "healthy")
    )
    monkeypatch.setattr(
        DefaultAgent, "_check_hf_token", lambda self, provider_cfg: (True, "valid token")
    )

    cfg = _base_config()
    cfg["provider"]["mode"] = "auto"
    agent = DefaultAgent(config=cfg)
    loaded = agent.get_config()
    assert loaded["provider_selected"] == "ollama"


def test_provider_auto_uses_hf_when_ollama_unavailable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        DefaultAgent, "_check_ollama_health", lambda self: (False, "connection refused")
    )
    monkeypatch.setattr(
        DefaultAgent, "_check_hf_token", lambda self, provider_cfg: (True, "valid token")
    )

    cfg = _base_config()
    cfg["provider"]["mode"] = "auto"
    agent = DefaultAgent(config=cfg)
    loaded = agent.get_config()
    assert loaded["provider_selected"] == "huggingface"


def test_provider_auto_falls_back_offline_when_external_missing(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        DefaultAgent, "_check_ollama_health", lambda self: (False, "connection refused")
    )
    monkeypatch.setattr(
        DefaultAgent, "_check_hf_token", lambda self, provider_cfg: (False, "no token")
    )

    cfg = _base_config()
    cfg["provider"]["mode"] = "auto"
    agent = DefaultAgent(config=cfg)
    loaded = agent.get_config()
    assert loaded["provider_selected"] == "offline"


def test_provider_auto_errors_when_external_required(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        DefaultAgent, "_check_ollama_health", lambda self: (False, "connection refused")
    )
    monkeypatch.setattr(
        DefaultAgent, "_check_hf_token", lambda self, provider_cfg: (False, "no token")
    )

    cfg = _base_config()
    cfg["provider"]["mode"] = "auto"
    cfg["provider"]["require_external"] = True
    with pytest.raises(RuntimeError, match="No external provider is available"):
        DefaultAgent(config=cfg)


# ------------------------------------------------------------------
# Day 2: per-tool gate tests for all 5 servers
# ------------------------------------------------------------------


def test_agent_gate_invokes_all_five_mcp_tools():
    """Each MCP server family should be dispatchable via the offline heuristic."""
    agent = DefaultAgent(config=_base_config())

    tool_payloads = [
        ("list_directory", "Please use list_directory to see files."),
        ("send_email", "Please use send_email to send a test message."),
        ("fetch_url", "Please use fetch_url to get https://example.com"),
        ("query_db", "Please use query_db to run `SELECT 1`"),
        ("execute_code", "Please use execute_code to run `print('hi')`"),
    ]

    invoked_tools: set[str] = set()
    for expected_tool, user_msg in tool_payloads:
        payload = AttackPayload(
            id=f"GATE-5TOOL-{expected_tool}",
            attack_module="gate_e2e",
            owasp_id="ASI02",
            category="Tool Invocation",
            messages=[{"role": "user", "content": user_msg}],
            expected_behavior=f"Agent invokes {expected_tool}.",
            severity=Severity.LOW,
        )
        response = agent.run(payload)
        # Filter out injected_tool_output
        real_calls = [tc for tc in response.tool_calls if tc.tool_name != "injected_tool_output"]
        assert len(real_calls) > 0, f"No tool calls for payload mentioning {expected_tool}"
        invoked_tools.update(tc.tool_name for tc in real_calls)

    expected = {"list_directory", "send_email", "fetch_url", "query_db", "execute_code"}
    assert expected.issubset(invoked_tools), f"Missing tools: {expected - invoked_tools}"


def test_agent_gate_database_tool_invocation():
    """Database tool insert_record should be dispatchable."""
    agent = DefaultAgent(config=_base_config())
    payload = AttackPayload(
        id="GATE-DB-001",
        attack_module="gate_e2e",
        owasp_id="ASI02",
        category="Tool Invocation",
        messages=[
            {"role": "user", "content": "use insert_record to add test data"}
        ],
        expected_behavior="Agent invokes insert_record.",
        severity=Severity.LOW,
    )
    response = agent.run(payload)
    real_calls = [tc for tc in response.tool_calls if tc.tool_name != "injected_tool_output"]
    assert len(real_calls) > 0
    assert real_calls[0].tool_name == "insert_record"


def test_ollama_health_check_verifies_model_presence():
    """Health check should return True when configured model is in /api/tags."""
    tags_json = json.dumps({"models": [{"name": "qwen3:4b"}, {"name": "llama3:8b"}]})
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = tags_json.encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    cfg = _base_config()
    cfg["provider"]["mode"] = "ollama"

    with patch("aegis.testbed.agent.urlopen", return_value=mock_response):
        agent = DefaultAgent(config=cfg)
    loaded = agent.get_config()
    assert loaded["provider_selected"] == "ollama"
    assert "present" in loaded["provider_note"]


def test_ollama_health_check_fails_when_model_missing(monkeypatch: pytest.MonkeyPatch):
    """Health check should fail when configured model is not in /api/tags."""
    tags_json = json.dumps({"models": [{"name": "llama3:8b"}]})
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = tags_json.encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    monkeypatch.setattr(
        DefaultAgent, "_check_hf_token", lambda self, provider_cfg: (False, "no token")
    )

    cfg = _base_config()
    cfg["provider"]["mode"] = "auto"

    with patch("aegis.testbed.agent.urlopen", return_value=mock_response):
        agent = DefaultAgent(config=cfg)
    loaded = agent.get_config()
    assert loaded["provider_selected"] == "offline"
    assert "not" in loaded["provider_note"].lower()


def test_default_server_set_includes_all_five():
    """Even if config omits 'database', all 5 server families should load."""
    cfg = _base_config()
    cfg["mcp_servers"] = ["filesystem", "email", "http"]  # deliberately missing database, code_exec

    agent = DefaultAgent(config=cfg)
    registry_keys = set(agent._tool_registry.keys())

    # Each server contributes at least one tool
    assert "list_directory" in registry_keys   # filesystem
    assert "send_email" in registry_keys       # email
    assert "fetch_url" in registry_keys        # http
    assert "query_db" in registry_keys         # database
    assert "execute_code" in registry_keys     # code_exec
