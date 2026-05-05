"""Tests for aegis/config.py — load_config() function."""
import pytest


class TestLoadConfig:
    def test_load_default_config(self):
        from aegis.config import load_config

        config = load_config()
        assert "testbed" in config
        assert "attacks" in config
        assert "evaluation" in config
        assert "defenses" in config
        assert "reporting" in config
        assert config["testbed"]["model"] == "qwen3:4b"
        assert config["testbed"]["provider"]["ollama_num_predict"] == 128
        assert config["testbed"]["security"]["code_exec_enabled"] is False

    def test_load_missing_file_raises(self):
        from aegis.config import load_config

        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")

    def test_load_invalid_yaml_raises(self, tmp_path):
        from aegis.config import load_config

        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("just a string, not a mapping")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_config(str(bad_file))

    def test_load_missing_required_keys_raises(self, tmp_path):
        from aegis.config import load_config

        partial = tmp_path / "partial.yaml"
        partial.write_text("testbed:\n  model: test\n")
        with pytest.raises(ValueError, match="missing required sections"):
            load_config(str(partial))

    def test_load_custom_config(self, tmp_path):
        from aegis.config import load_config

        custom = tmp_path / "custom.yaml"
        custom.write_text(
            "testbed:\n  model: custom\n"
            "attacks:\n  modules: []\n"
            "evaluation:\n  scorers: []\n"
            "defenses:\n  active: []\n"
            "reporting:\n  formats: [json]\n"
        )
        config = load_config(str(custom))
        assert config["testbed"]["model"] == "custom"
        assert "security" in config["testbed"]

    def test_load_config_accepts_path_object(self, tmp_path):
        from pathlib import Path

        from aegis.config import load_config

        custom = tmp_path / "path_test.yaml"
        custom.write_text(
            "testbed:\n  model: path-test\n"
            "attacks:\n  modules: []\n"
            "evaluation:\n  scorers: []\n"
            "defenses:\n  active: []\n"
            "reporting:\n  formats: [json]\n"
        )
        config = load_config(Path(custom))
        assert config["testbed"]["model"] == "path-test"

    def test_model_env_overrides_keep_docker_runs_configurable(self, monkeypatch):
        from aegis.config import load_config

        monkeypatch.setenv("AEGIS_TARGET_MODEL", "local-target:latest")
        config = load_config("aegis/config.local_single_qwen.yaml")

        assert config["testbed"]["model"] == "local-target:latest"
        assert config["testbed"]["fallback_model"] == "local-target:latest"
        assert config["evaluation"]["judge_model"] == "local-target:latest"

    def test_specific_judge_env_override_wins(self, monkeypatch):
        from aegis.config import load_config

        monkeypatch.setenv("AEGIS_TARGET_MODEL", "local-target:latest")
        monkeypatch.setenv("AEGIS_JUDGE_MODEL", "local-judge:latest")

        config = load_config("aegis/config.local_single_qwen.yaml")

        assert config["testbed"]["model"] == "local-target:latest"
        assert config["testbed"]["fallback_model"] == "local-target:latest"
        assert config["evaluation"]["judge_model"] == "local-judge:latest"

    def test_day7_core7_config_has_exactly_seven_core_modules(self):
        from aegis.config import load_config

        config = load_config("aegis/config.day7_core7.yaml")
        assert config["attacks"]["modules"] == [
            "asi01_goal_hijack",
            "asi02_tool_misuse",
            "asi04_supply_chain",
            "asi05_code_exec",
            "asi06_memory_poison",
            "mcp06_cmd_injection",
            "llm01_prompt_inject",
        ]


    def test_hosted_provider_template_loads(self):
        from aegis.config import load_config

        config = load_config("aegis/config.hosted.yaml")

        assert config["testbed"]["provider"]["mode"] == "openai_compat"
        assert config["testbed"]["provider"]["api_key_env"] == "OPENAI_API_KEY"
        assert config["evaluation"]["scorers"] == ["rule_based"]
        assert config["attacks"]["payloads_per_module"] <= 5

    def test_target_model_env_overrides_hosted_provider_model(self, monkeypatch):
        from aegis.config import load_config

        monkeypatch.setenv("AEGIS_TARGET_MODEL", "hosted-target")
        config = load_config("aegis/config.hosted.yaml")

        assert config["testbed"]["model"] == "hosted-target"
        assert config["testbed"]["provider"]["model"] == "hosted-target"

    def test_invalid_provider_mode_raises(self, tmp_path):
        from aegis.config import load_config

        custom = tmp_path / "bad-provider.yaml"
        custom.write_text(
            "testbed:\n"
            "  model: test\n"
            "  provider:\n"
            "    mode: typo_provider\n"
            "attacks:\n"
            "  modules: []\n"
            "evaluation:\n"
            "  scorers: [rule_based]\n"
            "defenses:\n"
            "  active: []\n"
            "reporting:\n"
            "  formats: [json]\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="provider.mode"):
            load_config(custom)

    def test_non_positive_payloads_per_module_raises(self, tmp_path):
        from aegis.config import load_config

        custom = tmp_path / "bad-payload-cap.yaml"
        custom.write_text(
            "testbed:\n"
            "  model: test\n"
            "attacks:\n"
            "  modules: []\n"
            "  payloads_per_module: 0\n"
            "evaluation:\n"
            "  scorers: [rule_based]\n"
            "defenses:\n"
            "  active: []\n"
            "reporting:\n"
            "  formats: [json]\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="attacks.payloads_per_module"):
            load_config(custom)
