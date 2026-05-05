"""Tests for hosted provider adapters."""
from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

import pytest


def _response(payload: object) -> MagicMock:
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


class TestOpenAICompatProvider:
    def test_api_key_available_uses_hash_not_raw_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import openai_compat

        monkeypatch.setenv("OPENAI_API_KEY", "test-secret-token")

        available, note = openai_compat.api_key_available({})

        assert available is True
        assert "test-secret-token" not in note
        assert re.search(r"sha256:[0-9a-f]{12}", note)

    def test_complete_parses_chat_completion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import openai_compat

        monkeypatch.setenv("OPENAI_API_KEY", "secret-token")
        captured = {}

        def _urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return _response({"choices": [{"message": {"content": "hosted answer"}}]})

        with patch("aegis.interfaces.openai_compat.urlopen", side_effect=_urlopen):
            output = openai_compat.complete(
                "prompt",
                {
                    "base_url": "https://api.example.test/v1",
                    "model": "provider-model",
                    "max_tokens": 42,
                    "timeout_seconds": 7,
                },
            )

        assert output == "hosted answer"
        assert captured["url"] == "https://api.example.test/v1/chat/completions"
        assert captured["body"]["model"] == "provider-model"
        assert captured["body"]["max_tokens"] == 42
        assert captured["timeout"] == 7

    def test_missing_key_fails_without_secret_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import openai_compat

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="OPENAI_API_KEY") as exc:
            openai_compat.complete("prompt", {})

        assert "secret" not in str(exc.value).lower()

    def test_configured_key_env_still_supported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import openai_compat

        monkeypatch.setenv("ACME_LLM_API_KEY", "test-secret-token")

        available, note = openai_compat.api_key_available({"api_key_env": "ACME_LLM_API_KEY"})

        assert available is True
        assert "ACME_LLM_API_KEY" in note
        assert "test-secret-token" not in note

    def test_invalid_base_url_fails_before_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import openai_compat

        monkeypatch.setenv("OPENAI_API_KEY", "secret-token")
        with pytest.raises(ValueError, match="base_url"):
            openai_compat.complete("prompt", {"base_url": "file:///tmp/socket"})

    def test_http_base_url_fails_before_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import openai_compat

        monkeypatch.setenv("OPENAI_API_KEY", "secret-token")
        with patch("aegis.interfaces.openai_compat.urlopen") as urlopen:
            with pytest.raises(ValueError, match="HTTPS URL"):
                openai_compat.complete("prompt", {"base_url": "http://api.example.test/v1"})

        urlopen.assert_not_called()

    @pytest.mark.parametrize(
        "base_url",
        [
            "https://token@example.test/v1",
            "https://user:token@example.test/v1",
            "https://api.example.test/v1?key=token",
            "https://api.example.test/v1#token",
        ],
    )
    def test_secret_bearing_base_url_rejected(
        self,
        monkeypatch: pytest.MonkeyPatch,
        base_url: str,
    ) -> None:
        from aegis.interfaces import openai_compat

        monkeypatch.setenv("OPENAI_API_KEY", "secret-token")
        with pytest.raises(ValueError, match="credentials|query|fragments"):
            openai_compat.complete("prompt", {"base_url": base_url})


class TestAnthropicProvider:
    def test_api_key_available_uses_hash_not_raw_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-secret-token")

        available, note = anthropic.api_key_available({})

        assert available is True
        assert "test-secret-token" not in note
        assert re.search(r"sha256:[0-9a-f]{12}", note)

    def test_complete_parses_messages_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import anthropic

        monkeypatch.setenv("ANTHROPIC_API_KEY", "secret-token")
        with patch(
            "aegis.interfaces.anthropic.urlopen",
            return_value=_response({"content": [{"type": "text", "text": "anthropic answer"}]}),
        ):
            output = anthropic.complete("prompt", {"model": "claude-test"})

        assert output == "anthropic answer"

    def test_missing_key_fails_without_secret_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import anthropic

        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY") as exc:
            anthropic.complete("prompt", {})

        assert "secret" not in str(exc.value).lower()


class TestHFInferenceProvider:
    def test_api_key_available_uses_hash_not_raw_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import hf_inference

        monkeypatch.setenv("HF_TOKEN", "test-secret-token")

        available, note = hf_inference.api_key_available({})

        assert available is True
        assert "test-secret-token" not in note
        assert re.search(r"sha256:[0-9a-f]{12}", note)

    def test_complete_parses_generated_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import hf_inference

        monkeypatch.setenv("HF_TOKEN", "secret-token")
        with patch(
            "aegis.interfaces.hf_inference.urlopen",
            return_value=_response([{"generated_text": "hf answer"}]),
        ):
            output = hf_inference.complete("prompt", {"model": "org/model"})

        assert output == "hf answer"

    def test_missing_key_fails_without_secret_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from aegis.interfaces import hf_inference

        monkeypatch.delenv("HF_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="HF_TOKEN") as exc:
            hf_inference.complete("prompt", {})

        assert "secret" not in str(exc.value).lower()
