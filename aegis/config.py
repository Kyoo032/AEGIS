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

    logger.info("AEGIS config loaded successfully from %s", path)
    return raw


def _validate_config(config: dict[str, Any], source_path: Path) -> None:
    """Validate presence of required top-level config sections."""
    missing = _REQUIRED_KEYS - config.keys()
    if missing:
        raise ValueError(
            f"Config file {source_path} is missing required sections: "
            f"{sorted(missing)}. "
            f"Required: {sorted(_REQUIRED_KEYS)}"
        )
