"""Tests for testbed agents, profiles, retry behavior, and multi-turn handling."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from aegis.models import AttackPayload, Severity
from aegis.testbed.agent import DefaultAgent
from aegis.testbed.mock_agent import MockAgent, MockResponse
from aegis.testbed.retry import LLMCallError, call_with_retry


@pytest.fixture(autouse=True)
def _stub_provider_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep unit tests local and deterministic (no real provider health calls)."""
    monkeypatch.setattr(DefaultAgent, "_check_ollama_health", lambda self: (False, "stubbed"))
    monkeypatch.setattr(
        DefaultAgent,
        "_check_hf_token",
        lambda self, provider_cfg: (False, "stubbed"),
    )


def _payload(
    payload_id: str = "TEST-AGENT-001",
    messages: list[dict[str, str]] | None = None,
) -> AttackPayload:
    return AttackPayload(
        id=payload_id,
        attack_module="test_module",
        owasp_id="LLM01",
        category="Test",
        messages=messages or [{"role": "user", "content": "hello"}],
        expected_behavior="safe",
        severity=Severity.LOW,
    )


def _offline_cfg(agent_profile: str = "default") -> dict:
    return {
        "agent_profile": agent_profile,
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
        "llm_timeout_seconds": 0.05,
        "llm_max_retries": 2,
        "llm_retry_base_delay_seconds": 0.001,
        "llm_retry_max_delay_seconds": 0.002,
        "llm_retry_jitter_seconds": 0.0,
    }


class TestMockAgent:
    def test_run_returns_valid_response(self):
        agent = MockAgent(default_response=MockResponse(final_output="ok"))
        response = agent.run(_payload())

        assert response.final_output == "ok"
        assert response.messages[-1]["role"] == "assistant"
        assert response.error is None

    def test_round_robin_response_cycling(self):
        agent = MockAgent(
            responses=[
                MockResponse(final_output="first"),
                MockResponse(final_output="second"),
            ]
        )

        r1 = agent.run(_payload("TEST-1"))
        r2 = agent.run(_payload("TEST-2"))
        r3 = agent.run(_payload("TEST-3"))

        assert [r1.final_output, r2.final_output, r3.final_output] == [
            "first",
            "second",
            "first",
        ]

    def test_history_and_tool_calls(self):
        agent = MockAgent(
            default_response=MockResponse(
                final_output="done",
                tool_calls=[
                    {
                        "tool_name": "read_file",
                        "parameters": {"path": "/tmp/file.txt"},
                        "result": "content",
                    }
                ],
            )
        )
        response = agent.run(_payload())

        assert response.tool_calls[0].tool_name == "read_file"
        assert response.tool_calls[0].parameters["path"] == "/tmp/file.txt"
        assert agent.run_count == 1
        assert len(agent.run_history) == 1

    def test_reset_clears_history_and_counter(self):
        agent = MockAgent(default_response=MockResponse(final_output="x"))
        agent.run(_payload("TEST-1"))
        assert agent.run_count == 1

        agent.reset()
        assert agent.run_count == 0
        assert agent.run_history == []

    def test_defense_and_context_tracking(self):
        agent = MockAgent(default_response=MockResponse(final_output="x"))
        agent.enable_defense("input_validator", {"strict": True})
        response = agent.run(_payload())

        assert response.defense_active == "input_validator"

        agent.inject_context("Injected RAG note", "rag")
        assert agent.injected_contexts[0]["method"] == "rag"

        agent.disable_defense("input_validator")
        response2 = agent.run(_payload("TEST-2"))
        assert response2.defense_active is None

    def test_multi_turn_payload_preserved(self):
        agent = MockAgent(default_response=MockResponse(final_output="ack"))
        history = [
            {"role": "system", "content": "policy"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
            {"role": "user", "content": "continue"},
        ]

        response = agent.run(_payload(messages=history))
        assert response.messages[:-1] == history
        assert response.messages[-1]["content"] == "ack"


class TestDefaultAgentProfiles:
    def test_default_profile_has_broad_servers(self):
        agent = DefaultAgent(config=_offline_cfg("default"))
        assert set(agent._configured_servers()) == {
            "filesystem",
            "http",
            "email",
            "database",
            "code_exec",
        }

    def test_hardened_profile_restricts_servers(self):
        agent = DefaultAgent(config=_offline_cfg("hardened"))
        assert set(agent._configured_servers()) == {"filesystem", "http", "email"}
        assert agent.get_config()["security"]["code_exec_enabled"] is False

    def test_minimal_profile_disables_rag_and_memory(self):
        agent = DefaultAgent(config=_offline_cfg("minimal"))
        cfg = agent.get_config()

        assert set(agent._configured_servers()) == {"filesystem"}
        assert cfg["rag_enabled"] is False
        assert cfg["memory_enabled"] is False

    def test_unknown_profile_falls_back_to_default(self):
        agent = DefaultAgent(config=_offline_cfg("unknown_profile"))
        cfg = agent.get_config()

        assert cfg["agent_profile"] == "default"
        assert set(agent._configured_servers()) == {
            "filesystem",
            "http",
            "email",
            "database",
            "code_exec",
        }


class TestDefaultAgentTimeoutRetry:
    def test_retry_config_is_loaded(self):
        agent = DefaultAgent(config=_offline_cfg("default"))
        cfg = agent.get_config()

        assert cfg["llm_timeout_seconds"] == 0.05
        assert cfg["llm_max_retries"] == 2

    def test_call_ollama_retries_on_transient_failure(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("aegis.testbed.retry.time.sleep", lambda *_: None)

        agent = DefaultAgent(config=_offline_cfg("default"))
        ok_response = MagicMock()
        ok_response.read.return_value = json.dumps({"response": "stable answer"}).encode("utf-8")
        ok_response.__enter__.return_value = ok_response
        ok_response.__exit__.return_value = False

        with patch(
            "aegis.testbed.agent.urlopen",
            side_effect=[URLError("temporary"), ok_response],
        ) as mocked_urlopen:
            output = agent._call_ollama("prompt")

        assert output == "stable answer"
        assert mocked_urlopen.call_count == 2

    def test_non_retryable_error_fails_fast(self):
        agent = DefaultAgent(config=_offline_cfg("default"))
        bad_response = MagicMock()
        bad_response.read.return_value = b"not-json"
        bad_response.__enter__.return_value = bad_response
        bad_response.__exit__.return_value = False

        with patch("aegis.testbed.agent.urlopen", return_value=bad_response) as mocked_urlopen:
            with pytest.raises(LLMCallError, match="non-retryable"):
                agent._call_ollama("prompt")

        assert mocked_urlopen.call_count == 1

    def test_fallback_on_exhaustion_sets_error(self, monkeypatch: pytest.MonkeyPatch):
        agent = DefaultAgent(config=_offline_cfg("default"))
        agent._provider_name = "ollama"

        def _raise(_: str) -> str:
            raise LLMCallError("retries exhausted")

        monkeypatch.setattr(agent, "_call_ollama", _raise)
        response = agent.run(_payload())

        assert response.error is not None
        assert "retries exhausted" in response.error
        assert response.raw_llm_output is None
        assert response.final_output.startswith("Processed payload")


class TestDefaultAgentMultiTurn:
    def test_single_turn_response(self):
        agent = DefaultAgent(config=_offline_cfg("default"))
        response = agent.run(_payload(messages=[{"role": "user", "content": "one"}]))

        assert len(response.messages) == 2
        assert response.messages[0]["content"] == "one"

    def test_four_message_history_preserved(self):
        agent = DefaultAgent(config=_offline_cfg("default"))
        history = [
            {"role": "system", "content": "policy"},
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "answer"},
            {"role": "user", "content": "follow-up"},
        ]
        response = agent.run(_payload(messages=history))

        assert response.messages[:-1] == history
        assert len(response.messages) == 5

    def test_memory_persists_across_runs(self):
        agent = DefaultAgent(config=_offline_cfg("default"))

        r1 = agent.run(_payload("TURN-1", [{"role": "user", "content": "first"}]))
        r2 = agent.run(_payload("TURN-2", [{"role": "user", "content": "second"}]))

        assert r1.memory_state is not None
        assert r2.memory_state is not None
        assert len(r2.memory_state["turns"]) >= len(r1.memory_state["turns"])

    def test_reset_clears_memory(self):
        agent = DefaultAgent(config=_offline_cfg("default"))
        agent.run(_payload("TURN-1", [{"role": "user", "content": "first"}]))
        agent.run(_payload("TURN-2", [{"role": "user", "content": "second"}]))
        agent.reset()

        r3 = agent.run(_payload("TURN-3", [{"role": "user", "content": "third"}]))
        assert r3.memory_state is not None
        assert len(r3.memory_state["turns"]) == 2


class TestRetryHelper:
    def test_success_first_try(self):
        calls = {"n": 0}

        def _ok() -> str:
            calls["n"] += 1
            return "ok"

        out = call_with_retry(
            _ok,
            max_retries=2,
            timeout_seconds=1.0,
            base_delay_seconds=0.01,
            max_delay_seconds=0.1,
            jitter_seconds=0.0,
            operation_name="unit",
        )
        assert out == "ok"
        assert calls["n"] == 1

    def test_retry_then_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("aegis.testbed.retry.time.sleep", lambda *_: None)
        calls = {"n": 0}

        def _flaky() -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("transient")
            return "ok"

        out = call_with_retry(
            _flaky,
            max_retries=2,
            timeout_seconds=1.0,
            base_delay_seconds=0.01,
            max_delay_seconds=0.1,
            jitter_seconds=0.0,
            operation_name="unit",
        )
        assert out == "ok"
        assert calls["n"] == 2

    def test_raise_after_max_retries(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("aegis.testbed.retry.time.sleep", lambda *_: None)
        calls = {"n": 0}

        def _always_timeout() -> str:
            calls["n"] += 1
            raise TimeoutError("still down")

        with pytest.raises(LLMCallError, match="failed after"):
            call_with_retry(
                _always_timeout,
                max_retries=2,
                timeout_seconds=1.0,
                base_delay_seconds=0.01,
                max_delay_seconds=0.1,
                jitter_seconds=0.0,
                operation_name="unit",
            )

        assert calls["n"] == 3

    def test_fail_fast_non_retryable(self):
        calls = {"n": 0}

        def _bad_request() -> str:
            calls["n"] += 1
            raise ValueError("bad payload")

        with pytest.raises(LLMCallError, match="non-retryable"):
            call_with_retry(
                _bad_request,
                max_retries=3,
                timeout_seconds=1.0,
                base_delay_seconds=0.01,
                max_delay_seconds=0.1,
                jitter_seconds=0.0,
                operation_name="unit",
            )

        assert calls["n"] == 1

    def test_http_429_is_retryable(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("aegis.testbed.retry.time.sleep", lambda *_: None)
        calls = {"n": 0}

        def _rate_limited() -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise HTTPError(
                    url="http://localhost/test",
                    code=429,
                    msg="Too Many Requests",
                    hdrs=None,
                    fp=None,
                )
            return "ok"

        out = call_with_retry(
            _rate_limited,
            max_retries=2,
            timeout_seconds=1.0,
            base_delay_seconds=0.01,
            max_delay_seconds=0.1,
            jitter_seconds=0.0,
            operation_name="unit",
        )

        assert out == "ok"
        assert calls["n"] == 2
