"""Configuration loading and profile resolution mixin for DefaultAgent."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from aegis.config import load_config

logger = logging.getLogger(__name__)

_ALL_KNOWN_SERVERS: frozenset[str] = frozenset({
    "filesystem", "http", "email", "database", "code_exec",
})


class _AgentConfigMixin:
    """Mixin: config loading, profile resolution, server list, and defense defaults."""

    def _resolve_testbed_config(
        self, config: str | dict[str, Any] | None
    ) -> tuple[dict[str, Any], list[str]]:
        loaded = load_config()
        defense_defaults = loaded.get("defenses", {}).get("config", {})
        if isinstance(defense_defaults, dict):
            self._defense_defaults = {
                str(name): dict(value)
                for name, value in defense_defaults.items()
                if isinstance(value, dict)
            }
        testbed_cfg = dict(loaded["testbed"])

        if isinstance(config, dict):
            testbed_cfg = self._merge_nested_dicts(testbed_cfg, config)

        provider_cfg = dict(testbed_cfg.get("provider", {}))
        security_cfg = dict(testbed_cfg.get("security", {}))
        provider_cfg.setdefault("mode", "auto")
        provider_cfg.setdefault("hf_token_env", "HF_TOKEN")
        provider_cfg.setdefault("hf_model", "HuggingFaceH4/zephyr-7b-beta")
        provider_cfg.setdefault("ollama_base_url", "http://localhost:11434")
        provider_cfg.setdefault("ollama_health_timeout_seconds", 3)
        provider_cfg.setdefault("ollama_generate_timeout_seconds", 90)
        provider_cfg.setdefault("ollama_num_predict", 128)
        provider_cfg.setdefault("ollama_keep_alive", "15m")
        provider_cfg.setdefault("api_key_env", "")
        provider_cfg.setdefault("base_url", "")
        provider_cfg.setdefault("model", "")
        provider_cfg.setdefault("timeout_seconds", testbed_cfg.get("llm_timeout_seconds", 30))
        provider_cfg.setdefault("max_tokens", 256)
        if provider_cfg.get("model"):
            testbed_cfg["model"] = str(provider_cfg["model"])
        provider_cfg.setdefault("require_external", False)
        security_cfg.setdefault("memory_max_turns", 200)
        security_cfg.setdefault("rag_max_items", 200)
        security_cfg.setdefault("kb_enabled", True)
        security_cfg.setdefault("kb_max_docs", 500)
        security_cfg.setdefault("kb_retrieval_top_k", 5)
        security_cfg.setdefault("kb_attach_top_n", 3)
        security_cfg.setdefault("kb_mode", "baseline")
        security_cfg.setdefault("kb_trust_enforcement", "warn")
        security_cfg.setdefault("kb_seed_repo_docs", True)
        security_cfg.setdefault("kb_corpus_paths", [])
        security_cfg.setdefault("kb_fixture_paths", [])
        security_cfg.setdefault("code_exec_enabled", False)
        testbed_cfg["provider"] = provider_cfg
        testbed_cfg["security"] = security_cfg
        profile_defenses: list[str] = []

        if config == "test":
            testbed_cfg["agent_profile"] = "test"
            testbed_cfg["memory_enabled"] = False
            provider_cfg["mode"] = "offline"
            security_cfg["code_exec_enabled"] = True
        else:
            profile_defenses = self._apply_profile(testbed_cfg)

        self._add_provider_host_to_http_allowlist(provider_cfg, security_cfg)
        return testbed_cfg, profile_defenses

    def _apply_profile(self, testbed_cfg: dict[str, Any]) -> list[str]:
        profiles = testbed_cfg.get("profiles", {})
        if not isinstance(profiles, dict):
            profiles = {}

        selected = str(testbed_cfg.get("agent_profile", "default"))
        if selected not in profiles:
            if selected != "default":
                logger.warning("Unknown agent_profile '%s'; falling back to 'default'", selected)
            selected = "default"
        profile_cfg = profiles.get(selected, {})
        if not isinstance(profile_cfg, dict):
            profile_cfg = {}

        for key in ("mcp_servers", "rag_enabled", "memory_enabled", "restrict_servers"):
            if key in profile_cfg:
                testbed_cfg[key] = profile_cfg[key]

        security_cfg = dict(testbed_cfg.get("security", {}))
        security_overrides = profile_cfg.get("security_overrides", {})
        if isinstance(security_overrides, dict):
            security_cfg = self._merge_nested_dicts(security_cfg, security_overrides)
        testbed_cfg["security"] = security_cfg
        testbed_cfg["agent_profile"] = selected

        defenses_active = profile_cfg.get("defenses_active", [])
        if not isinstance(defenses_active, list):
            return []
        return [str(name) for name in defenses_active]

    def _configured_servers(self) -> list[str]:
        servers = self._config.get("mcp_servers", [])
        restrict = bool(self._config.get("restrict_servers", False))
        if not isinstance(servers, list):
            configured = set() if restrict else set(_ALL_KNOWN_SERVERS)
        elif restrict:
            configured = {str(n) for n in servers}
        else:
            configured = {str(n) for n in servers} | _ALL_KNOWN_SERVERS

        if not bool(self._security.get("code_exec_enabled", False)):
            configured.discard("code_exec")
        return sorted(configured)

    def _merge_nested_dicts(
        self,
        base: dict[str, Any],
        override: dict[str, Any],
    ) -> dict[str, Any]:
        out = dict(base)
        for key, value in override.items():
            if isinstance(out.get(key), dict) and isinstance(value, dict):
                out[key] = self._merge_nested_dicts(out[key], value)
            else:
                out[key] = value
        return out

    def _add_provider_host_to_http_allowlist(
        self,
        provider_cfg: dict[str, Any],
        security_cfg: dict[str, Any],
    ) -> None:
        allowlist = security_cfg.get("http_allowlist", [])
        if not isinstance(allowlist, list):
            allowlist = []
        urls = [str(provider_cfg.get("ollama_base_url", "http://localhost:11434"))]
        mode = str(provider_cfg.get("mode", "auto"))
        if mode == "openai_compat" and provider_cfg.get("base_url"):
            urls.append(str(provider_cfg["base_url"]))
        elif mode == "anthropic":
            urls.append(str(provider_cfg.get("base_url") or "https://api.anthropic.com"))
        elif mode == "hf_inference":
            urls.append(str(provider_cfg.get("base_url") or "https://api-inference.huggingface.co"))

        for base_url in urls:
            host = (urlparse(base_url).hostname or "").strip().lower()
            if host and host not in allowlist:
                allowlist.append(host)
        security_cfg["http_allowlist"] = allowlist

    def _default_defense_config(self, defense_name: str) -> dict[str, Any]:
        candidate = self._defense_defaults.get(defense_name, {})
        return dict(candidate) if isinstance(candidate, dict) else {}
