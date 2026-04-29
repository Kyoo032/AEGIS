"""Configuration loader for AEGIS.

Reads aegis/config.yaml and returns a validated dict.
All tracks call load_config() to get the shared configuration.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"testbed", "attacks", "evaluation", "defenses", "reporting"}
)

_PROVIDER_MODES: frozenset[str] = frozenset(
    {
        "auto",
        "ollama",
        "huggingface",
        "offline",
        "openai_compat",
        "anthropic",
        "hf_inference",
    }
)

_DEFAULTS: dict[str, Any] = {
    "testbed": {
        "model": "qwen3:4b",
        "fallback_model": "qwen3:1.7b",
        "context_length": 4096,
        "model_provider": "ollama",
        "provider": {
            "mode": "auto",
            "ollama_base_url": "http://localhost:11434",
            "ollama_health_timeout_seconds": 3,
            "ollama_generate_timeout_seconds": 90,
            "ollama_num_predict": 128,
            "ollama_keep_alive": "15m",
            "hf_model": "HuggingFaceH4/zephyr-7b-beta",
            "hf_token_env": "HF_TOKEN",
            "api_key_env": "",
            "base_url": "",
            "model": "",
            "timeout_seconds": 30,
            "max_tokens": 256,
            "require_external": False,
        },
        "agent_profile": "default",
        "llm_timeout_seconds": 30,
        "llm_max_retries": 3,
        "llm_retry_base_delay_seconds": 0.5,
        "llm_retry_max_delay_seconds": 8.0,
        "llm_retry_jitter_seconds": 0.25,
        "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
        "rag_enabled": True,
        "memory_enabled": True,
        "profiles": {
            "default": {
                "mcp_servers": ["filesystem", "http", "email", "database", "code_exec"],
                "rag_enabled": True,
                "memory_enabled": True,
                "defenses_active": [],
                "restrict_servers": False,
                "security_overrides": {"code_exec_enabled": True},
            },
            "hardened": {
                "mcp_servers": ["filesystem", "http", "email"],
                "rag_enabled": True,
                "memory_enabled": True,
                "defenses_active": ["input_validator"],
                "restrict_servers": True,
                "security_overrides": {"code_exec_enabled": False},
            },
            "minimal": {
                "mcp_servers": ["filesystem"],
                "rag_enabled": False,
                "memory_enabled": False,
                "defenses_active": [],
                "restrict_servers": True,
                "security_overrides": {"code_exec_enabled": False},
            },
            "supply_chain": {
                "mcp_servers": [
                    "filesystem",
                    "http",
                    "email",
                    "database",
                    "code_exec",
                    "evil",
                ],
                "rag_enabled": True,
                "memory_enabled": True,
                "defenses_active": [],
                "restrict_servers": True,
                "security_overrides": {"code_exec_enabled": True},
            },
        },
        "security": {
            "http_allowlist": ["localhost", "127.0.0.1", "::1"],
            "http_block_private_networks": True,
            "http_max_response_bytes": 8192,
            "http_timeout_seconds": 8,
            "http_allow_redirects": False,
            "filesystem_safe_root": "/tmp/aegis_fs",
            "filesystem_max_read_bytes": 1_048_576,
            "filesystem_max_write_bytes": 1_048_576,
            "database_max_rows": 1000,
            "database_timeout_seconds": 2.0,
            "email_max_inbox_items": 200,
            "email_max_body_chars": 20_000,
            "memory_max_turns": 200,
            "rag_max_items": 200,
            "kb_enabled": True,
            "kb_max_docs": 500,
            "kb_max_chunks_per_doc": 8,
            "kb_retrieval_top_k": 5,
            "kb_attach_top_n": 3,
            "kb_mode": "baseline",
            "kb_trust_enforcement": "warn",
            "kb_seed_repo_docs": True,
            "kb_corpus_paths": ["datasets/kb/project_corpus.jsonl"],
            "kb_fixture_paths": [
                "datasets/kb_fixtures/clean_ops.jsonl",
                "datasets/kb_fixtures/asi06_poison.jsonl",
            ],
            "code_exec_enabled": False,
            "code_exec_timeout_seconds": 3,
            "code_exec_max_output_chars": 8000,
            "code_exec_max_code_chars": 8000,
        },
    },
    "attacks": {
        "modules": [
            "asi01_goal_hijack",
            "asi02_tool_misuse",
            "asi03_identity_privilege",
            "asi_dynamic_cloak",
            "asi_semantic_manip",
            "llm01_crosslingual",
            "asi07_inter_agent",
            "asi_hitl",
            "asi09_human_trust",
            "asi04_supply_chain",
            "asi05_code_exec",
            "asi06_memory_poison",
            "mcp06_cmd_injection",
            "llm01_prompt_inject",
            "llm02_data_disclosure",
        ],
        "payloads_per_module": 10,
        "multi_turn": True,
    },
    "evaluation": {
        "scorers": ["rule_based"],
        "judge_model": "qwen3:1.7b",
        "judge_timeout_seconds": 120,
        "judge_max_retries": 3,
        "judge_num_predict": 128,
        "judge_keep_alive": "15m",
        "judge_hard_fail": True,
        "confidence_threshold": 0.7,
    },
    "defenses": {
        "active": [],
        "available": [
            "input_validator",
            "output_filter",
            "tool_boundary",
            "mcp_integrity",
            "permission_enforcer",
        ],
        "layered_combinations": [
            ["input_validator", "output_filter", "tool_boundary"],
            ["mcp_integrity", "permission_enforcer"],
            [
                "input_validator",
                "output_filter",
                "tool_boundary",
                "mcp_integrity",
                "permission_enforcer",
            ],
        ],
        "config": {
            "tool_boundary": {
                "strict": True,
                "max_calls_per_run": 5,
                "allowed_tools": [],
                "allowed_sequences": {},
                "param_block_patterns": [
                    r"(?:\$\(|`|;\s*|&&|\|\|)",
                    r"(?:\.\./|/etc/passwd|/etc/shadow)",
                    r"(?:drop\s+table|union\s+select|;\s*select)",
                ],
            },
            "mcp_integrity": {
                "strict": True,
                "allow_new_tools": False,
                "verify_doc_hash": True,
            },
            "permission_enforcer": {
                "mode": "standard",
                "allowed_tools": [],
                "tool_permissions": {},
                "forbidden_cross_tool_flows": [
                    {
                        "from_tools": ["read_file", "query_db", "read_inbox"],
                        "to_tools": ["send_email", "post_request", "fetch_url"],
                    }
                ],
            },
        },
    },
    "reporting": {
        "formats": ["json", "html"],
        "output_dir": "./reports",
        "include_atlas_mapping": True,
    },
}


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate the AEGIS configuration file.

    Args:
        config_path: Path to a YAML config file.
                     Defaults to aegis/config.yaml bundled with the package.

    Returns:
        Validated configuration dict with all top-level sections present.

    Raises:
        FileNotFoundError: If the specified config file does not exist.
        ValueError: If the config is missing required top-level keys.
        yaml.YAMLError: If the file is not valid YAML.
    """
    path = Path(config_path) if config_path is not None else _DEFAULT_CONFIG_PATH

    if not path.exists():
        raise FileNotFoundError(
            f"AEGIS config file not found: {path}. "
            f"Default config is at {_DEFAULT_CONFIG_PATH}"
        )

    logger.debug("Loading AEGIS config from %s", path)

    with path.open("r", encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(
            f"Config file {path} must contain a YAML mapping at the top level, "
            f"got {type(raw).__name__}"
        )

    _validate_config(raw, path)
    merged = _deep_merge(_DEFAULTS, raw)

    # Environment variable overrides
    provider_mode = os.environ.get("AEGIS_PROVIDER_MODE")
    if provider_mode:
        merged["testbed"]["provider"]["mode"] = provider_mode

    ollama_url = os.environ.get("OLLAMA_BASE_URL")
    if ollama_url:
        merged["testbed"]["provider"]["ollama_base_url"] = ollama_url

    target_model = os.environ.get("AEGIS_TARGET_MODEL") or os.environ.get("AEGIS_MODEL")
    fallback_model = os.environ.get("AEGIS_FALLBACK_MODEL") or target_model
    judge_model = os.environ.get("AEGIS_JUDGE_MODEL") or target_model
    if target_model:
        merged["testbed"]["model"] = target_model
        merged["testbed"]["provider"]["model"] = target_model
    if fallback_model:
        merged["testbed"]["fallback_model"] = fallback_model
    if judge_model:
        merged["evaluation"]["judge_model"] = judge_model

    _validate_nested(merged, path)

    logger.info("AEGIS config loaded successfully from %s", path)
    return merged


def _validate_config(config: dict[str, Any], source_path: Path) -> None:
    """Validate presence of required top-level config sections."""
    missing = _REQUIRED_KEYS - config.keys()
    if missing:
        raise ValueError(
            f"Config file {source_path} is missing required sections: "
            f"{sorted(missing)}. "
            f"Required: {sorted(_REQUIRED_KEYS)}"
        )


def _deep_merge(defaults: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in defaults.items():
        if key not in overrides:
            out[key] = value
            continue
        candidate = overrides[key]
        if isinstance(value, dict) and isinstance(candidate, dict):
            out[key] = _deep_merge(value, candidate)
        else:
            out[key] = candidate
    for key, value in overrides.items():
        if key not in out:
            out[key] = value
    return out


def _validate_nested(config: dict[str, Any], source_path: Path) -> None:
    testbed = config["testbed"]
    if not isinstance(testbed, dict):
        raise ValueError(f"{source_path}: 'testbed' must be a mapping.")

    provider = testbed.get("provider")
    if not isinstance(provider, dict):
        raise ValueError(f"{source_path}: 'testbed.provider' must be a mapping.")

    security = testbed.get("security")
    if not isinstance(security, dict):
        raise ValueError(f"{source_path}: 'testbed.security' must be a mapping.")

    list_keys = (
        ("testbed.mcp_servers", testbed.get("mcp_servers")),
        ("attacks.modules", config["attacks"].get("modules")),
        ("evaluation.scorers", config["evaluation"].get("scorers")),
        ("defenses.active", config["defenses"].get("active")),
        ("defenses.available", config["defenses"].get("available")),
        ("defenses.layered_combinations", config["defenses"].get("layered_combinations")),
        ("reporting.formats", config["reporting"].get("formats")),
        ("testbed.security.http_allowlist", security.get("http_allowlist")),
    )
    for name, value in list_keys:
        if not isinstance(value, list):
            raise ValueError(f"{source_path}: '{name}' must be a list.")

    if not isinstance(security.get("code_exec_enabled"), bool):
        raise ValueError(f"{source_path}: 'testbed.security.code_exec_enabled' must be bool.")
    if not isinstance(security.get("http_block_private_networks"), bool):
        raise ValueError(
            f"{source_path}: 'testbed.security.http_block_private_networks' must be bool."
        )
    if not isinstance(provider.get("ollama_keep_alive"), str):
        raise ValueError(f"{source_path}: 'testbed.provider.ollama_keep_alive' must be str.")
    if not isinstance(provider.get("require_external"), bool):
        raise ValueError(f"{source_path}: 'testbed.provider.require_external' must be bool.")
    provider_mode = str(provider.get("mode", "auto"))
    if provider_mode not in _PROVIDER_MODES:
        raise ValueError(
            f"{source_path}: 'testbed.provider.mode' must be one of "
            f"{sorted(_PROVIDER_MODES)}, got {provider_mode!r}."
        )
    payloads_per_module = config["attacks"].get("payloads_per_module")
    if (
        isinstance(payloads_per_module, bool)
        or not isinstance(payloads_per_module, int)
        or payloads_per_module <= 0
    ):
        raise ValueError(f"{source_path}: 'attacks.payloads_per_module' must be a positive int.")

    number_keys = (
        ("testbed.provider.ollama_health_timeout_seconds", provider.get("ollama_health_timeout_seconds")),
        ("testbed.provider.ollama_generate_timeout_seconds", provider.get("ollama_generate_timeout_seconds")),
        ("testbed.provider.ollama_num_predict", provider.get("ollama_num_predict")),
        ("testbed.provider.timeout_seconds", provider.get("timeout_seconds")),
        ("testbed.provider.max_tokens", provider.get("max_tokens")),
        ("evaluation.judge_timeout_seconds", config["evaluation"].get("judge_timeout_seconds")),
        ("evaluation.judge_max_retries", config["evaluation"].get("judge_max_retries")),
        ("evaluation.judge_num_predict", config["evaluation"].get("judge_num_predict")),
    )
    for key, value in number_keys:
        if not isinstance(value, (int, float)):
            raise ValueError(f"{source_path}: '{key}' must be numeric.")
        if value <= 0:
            raise ValueError(f"{source_path}: '{key}' must be greater than zero.")

    if not isinstance(config["evaluation"].get("judge_hard_fail"), bool):
        raise ValueError(f"{source_path}: 'evaluation.judge_hard_fail' must be bool.")
    if not isinstance(config["evaluation"].get("judge_keep_alive"), str):
        raise ValueError(f"{source_path}: 'evaluation.judge_keep_alive' must be str.")

    profiles = testbed.get("profiles")
    if not isinstance(profiles, dict):
        raise ValueError(f"{source_path}: 'testbed.profiles' must be a mapping.")
    for name, profile_cfg in profiles.items():
        if not isinstance(profile_cfg, dict):
            raise ValueError(
                f"{source_path}: 'testbed.profiles.{name}' must be a mapping."
            )
        for key in ("mcp_servers", "defenses_active"):
            value = profile_cfg.get(key, [])
            if not isinstance(value, list):
                raise ValueError(
                    f"{source_path}: 'testbed.profiles.{name}.{key}' must be a list."
                )
        restrict_servers = profile_cfg.get("restrict_servers", False)
        if not isinstance(restrict_servers, bool):
            raise ValueError(
                f"{source_path}: 'testbed.profiles.{name}.restrict_servers' must be bool."
            )
        security_overrides = profile_cfg.get("security_overrides", {})
        if not isinstance(security_overrides, dict):
            raise ValueError(
                f"{source_path}: 'testbed.profiles.{name}.security_overrides' must be a mapping."
            )

    defenses = config.get("defenses")
    if not isinstance(defenses, dict):
        raise ValueError(f"{source_path}: 'defenses' must be a mapping.")

    defense_cfg = defenses.get("config", {})
    if not isinstance(defense_cfg, dict):
        raise ValueError(f"{source_path}: 'defenses.config' must be a mapping.")

    for idx, combo in enumerate(defenses.get("layered_combinations", [])):
        if not isinstance(combo, list):
            raise ValueError(
                f"{source_path}: 'defenses.layered_combinations[{idx}]' must be a list."
            )
