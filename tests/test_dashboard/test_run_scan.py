"""Tests for Streamlit Run Scan helpers."""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest


class TestRunScanHelpers:
    def test_build_scan_config_uses_hosted_provider_fields(self, tmp_path) -> None:
        from dashboard.pages.run_scan import _build_scan_config

        config = _build_scan_config(
            provider_mode="openai_compat",
            api_key_env="PROVIDER_API_KEY",
            base_url="https://api.example.com/v1/",
            model="llama-test",
            modules=["llm01_prompt_inject"],
            payloads_per_module=3,
            output_dir=tmp_path,
        )

        provider = config["testbed"]["provider"]
        assert provider["mode"] == "openai_compat"
        assert provider["api_key_env"] == "PROVIDER_API_KEY"
        assert provider["base_url"] == "https://api.example.com/v1"
        assert provider["model"] == "llama-test"
        assert config["evaluation"]["scorers"] == ["rule_based"]
        assert config["reporting"]["output_dir"] == str(tmp_path)

    def test_build_scan_config_rejects_unknown_provider(self, tmp_path) -> None:
        from dashboard.pages.run_scan import _build_scan_config

        try:
            _build_scan_config(
                provider_mode="unexpected",
                api_key_env="PROVIDER_API_KEY",
                base_url="https://api.example.com/v1",
                model="llama-test",
                modules=["llm01_prompt_inject"],
                payloads_per_module=3,
                output_dir=tmp_path,
            )
        except ValueError as exc:
            assert "Unsupported provider mode" in str(exc)
        else:
            raise AssertionError("expected provider validation failure")

    def test_build_scan_config_rejects_insecure_base_url(self, tmp_path) -> None:
        from dashboard.pages.run_scan import _build_scan_config

        try:
            _build_scan_config(
                provider_mode="openai_compat",
                api_key_env="PROVIDER_API_KEY",
                base_url="http://api.example.com/v1",
                model="llama-test",
                modules=["llm01_prompt_inject"],
                payloads_per_module=3,
                output_dir=tmp_path,
            )
        except ValueError as exc:
            assert "HTTPS URL" in str(exc)
        else:
            raise AssertionError("expected HTTPS validation failure")

    @pytest.mark.parametrize(
        "base_url",
        [
            "https://token@example.com/v1",
            "https://user:token@example.com/v1",
            "https://api.example.com/v1?key=token",
            "https://api.example.com/v1#token",
        ],
    )
    def test_build_scan_config_rejects_secret_bearing_base_url(
        self,
        tmp_path,
        base_url: str,
    ) -> None:
        from dashboard.pages.run_scan import _build_scan_config

        with pytest.raises(ValueError, match="credentials|query|fragments"):
            _build_scan_config(
                provider_mode="openai_compat",
                api_key_env="PROVIDER_API_KEY",
                base_url=base_url,
                model="llama-test",
                modules=["llm01_prompt_inject"],
                payloads_per_module=3,
                output_dir=tmp_path,
            )

    def test_build_scan_config_rejects_placeholder_hosted_model(self, tmp_path) -> None:
        from dashboard.pages.run_scan import _build_scan_config

        try:
            _build_scan_config(
                provider_mode="openai_compat",
                api_key_env="PROVIDER_API_KEY",
                base_url="https://api.example.com/v1",
                model="replace-with-provider-model",
                modules=["llm01_prompt_inject"],
                payloads_per_module=3,
                output_dir=tmp_path,
            )
        except ValueError as exc:
            assert "concrete hosted model" in str(exc)
        else:
            raise AssertionError("expected model validation failure")

    def test_temporary_api_key_restores_environment(self, monkeypatch) -> None:
        from dashboard.pages.run_scan import _temporary_api_key

        monkeypatch.setenv("PROVIDER_KEY", "original")
        with _temporary_api_key("PROVIDER_KEY", "temporary"):
            assert os.environ["PROVIDER_KEY"] == "temporary"
        assert os.environ["PROVIDER_KEY"] == "original"

    def test_temporary_api_key_removes_new_environment(self, monkeypatch) -> None:
        from dashboard.pages.run_scan import _temporary_api_key

        monkeypatch.delenv("PROVIDER_KEY", raising=False)
        with _temporary_api_key("PROVIDER_KEY", "temporary"):
            assert os.environ["PROVIDER_KEY"] == "temporary"
        assert "PROVIDER_KEY" not in os.environ

    def test_invalid_form_does_not_consume_rate_limit(self, monkeypatch, tmp_path) -> None:
        from dashboard.pages import run_scan

        fake_st = MagicMock()
        fake_st.form.return_value.__enter__.return_value = None
        fake_st.form.return_value.__exit__.return_value = False
        fake_st.selectbox.return_value = "Generic chat-completions API"
        fake_st.text_input.side_effect = ["replace-with-provider-model", "https://api.example.com/v1", "key"]
        fake_st.multiselect.return_value = ["llm01_prompt_inject"]
        fake_st.slider.return_value = 1
        fake_st.form_submit_button.return_value = True
        monkeypatch.setattr(run_scan, "st", fake_st)
        monkeypatch.setattr(
            run_scan,
            "load_config",
            lambda: {"attacks": {"modules": ["llm01_prompt_inject"]}},
        )
        monkeypatch.setattr(run_scan, "get_session_report_dir", lambda: tmp_path)
        check_rate_limit = MagicMock(return_value=(True, 0, "ok"))
        monkeypatch.setattr(run_scan, "check_rate_limit", check_rate_limit)

        run_scan.render_run_scan()

        check_rate_limit.assert_not_called()
        fake_st.error.assert_called_once()


class TestRateLimit:
    def test_rate_limit_allows_then_blocks(self) -> None:
        from dashboard.utils import rate_limit

        rate_limit._HOURLY_EVENTS.clear()
        rate_limit._DAILY_EVENTS.clear()

        assert rate_limit.check_rate_limit("client", hourly_limit=2, daily_limit=10, now=100.0)[0] is True
        assert rate_limit.check_rate_limit("client", hourly_limit=2, daily_limit=10, now=101.0)[0] is True
        allowed, retry_after, reason = rate_limit.check_rate_limit(
            "client",
            hourly_limit=2,
            daily_limit=10,
            now=102.0,
        )

        assert allowed is False
        assert retry_after > 0
        assert "hourly" in reason
