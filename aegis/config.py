"""Configuration loader for AEGIS.

Reads aegis/config.yaml and returns a validated dict.
All tracks call load_config() to get the shared configuration.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"testbed", "attacks", "evaluation", "defenses", "reporting"}
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
            "hf_model": "HuggingFaceH4/zephyr-7b-beta",
            "hf_token_env": "HF_TOKEN",
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
                "security_overrides": {},
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
