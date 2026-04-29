"""Base attack module convenience class.

Provides shared boilerplate for all AEGIS attack modules:
YAML payload loading, payload building with module-level defaults,
execute flow with agent reset, and metadata generation.

Subclasses only need to set class attributes and optionally
override ``_filter_payloads``.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from pydantic import ValidationError

from aegis.interfaces.agent import AgentInterface
from aegis.interfaces.attack import AttackModule
from aegis.models import AttackPayload, AttackResult

_SAFE_MODULE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TOOL_ALIASES: dict[str, str] = {
    "db": "database",
    "database": "database",
}
_EXPORT_METADATA_KEYS = {
    "technique_tag": "technique",
    "is_negative_control": "negative_control",
    "attack_family": "attack_family",
    "version": "version",
}


class BaseAttackModule(AttackModule):
    """Convenience base class implementing ``AttackModule`` ABC boilerplate.

    Subclasses must set:
        name: str — module name, also used to locate the YAML file
        owasp_id: str — OWASP category ID
        atlas_technique: str | None — MITRE ATLAS technique ID (optional)
        description: str — human-readable description (optional)
    """

    name: str = ""
    owasp_id: str = ""
    atlas_technique: str | None = None
    description: str = ""
    category: str = ""
    default_severity: str = "high"
    supports_multi_turn: bool = False
    max_turns: int = 1

    def __init__(self) -> None:
        self._payloads: list[AttackPayload] | None = None

    # ------------------------------------------------------------------
    # Public API (implements AttackModule ABC)
    # ------------------------------------------------------------------

    def generate_payloads(
        self, target_config: dict[str, Any]
    ) -> list[AttackPayload]:
        """Load YAML, build AttackPayload objects, filter, store & return copy."""
        raw = self._load_payloads_from_yaml()
        payloads = self._build_attack_payloads(raw)
        payloads = self._filter_payloads(payloads, target_config)
        self._payloads = list(payloads)
        return list(self._payloads)

    def execute(self, agent: AgentInterface) -> list[AttackResult]:
        """Run all payloads against the agent, return results.

        For each payload: reset agent, send payload, wrap response in
        ``AttackResult`` with UTC timestamp and shared ``run_id``.

        Raises:
            RuntimeError: If ``generate_payloads`` has not been called yet.
        """
        if self._payloads is None:
            msg = (
                "No payloads loaded. Call generate_payloads() before execute()."
            )
            raise RuntimeError(msg)

        if not self._payloads:
            return []

        run_id = str(uuid4())
        results: list[AttackResult] = []

        for payload in self._payloads:
            agent.reset()
            payload_for_run = self._prepare_payload_for_run(payload, agent)
            response = agent.run(payload_for_run)
            result = AttackResult(
                payload=payload,
                response=response,
                timestamp=datetime.now(UTC),
                run_id=run_id,
            )
            results.append(result)

        return results

    def limit_payloads(self, max_count: int) -> None:
        """Trim generated payloads to the first ``max_count`` entries."""
        if self._payloads is None:
            return
        self._payloads = self._payloads[:max(0, int(max_count))]

    def get_metadata(self) -> dict[str, Any]:
        """Return module metadata for reporting."""
        return {
            "name": self.name,
            "owasp_id": self.owasp_id,
            "owasp_category": self.category,
            "atlas_technique": self.atlas_technique,
            "mitre_atlas_id": self.atlas_technique,
            "description": self.description,
            "payload_count": len(self._payloads) if self._payloads else 0,
            "supports_multi_turn": self.supports_multi_turn,
            "max_turns": self.max_turns,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_payload_path(self) -> Path:
        """Resolve path to this module's YAML payload file.

        Raises:
            ValueError: If the module name would escape the payloads directory.
        """
        package_payloads_dir = Path(__file__).parent / "payloads"
        dataset_payloads_dir = Path.cwd() / "datasets" / "payloads"

        if not _SAFE_MODULE_NAME.match(self.name):
            msg = (
                f"Invalid module name '{self.name}'. "
                f"Must match pattern: {_SAFE_MODULE_NAME.pattern}"
            )
            raise ValueError(msg)

        candidate_dirs = [package_payloads_dir, dataset_payloads_dir]
        for payloads_dir in candidate_dirs:
            resolved = (payloads_dir / f"{self.name}.yaml").resolve()
            if not resolved.is_relative_to(payloads_dir.resolve()):
                msg = (
                    f"Invalid module name '{self.name}': "
                    f"payload path must stay within {payloads_dir}"
                )
                raise ValueError(msg)
            if resolved.exists():
                return resolved

        return (package_payloads_dir / f"{self.name}.yaml").resolve()

    def _load_payloads_from_yaml(self) -> dict[str, Any]:
        """Parse YAML file, validate structure, return raw dict.

        Raises:
            FileNotFoundError: If the YAML file does not exist.
            ValueError: If required top-level keys are missing.
        """
        path = self._get_payload_path()

        if not path.exists():
            msg = f"Payload YAML file not found: {path}"
            raise FileNotFoundError(msg)

        with path.open("r", encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh)

        if not isinstance(raw, dict):
            msg = f"Payload YAML must be a mapping, got {type(raw).__name__}"
            raise ValueError(msg)

        if "module" not in raw:
            msg = f"Payload YAML missing required 'module' section: {path}"
            raise ValueError(msg)

        if "payloads" not in raw:
            msg = f"Payload YAML missing required 'payloads' section: {path}"
            raise ValueError(msg)

        return raw

    def _build_attack_payloads(
        self, raw: dict[str, Any]
    ) -> list[AttackPayload]:
        """Merge module-level defaults with per-payload data, build models.

        Module-level fields (attack_module, owasp_id, atlas_technique,
        category) serve as defaults; per-payload fields override them.

        Raises:
            ValueError: If payload structure is invalid or construction fails.
        """
        module_defaults: dict[str, Any] = dict(raw.get("module", {}))
        raw_payloads = raw.get("payloads", [])

        if not isinstance(raw_payloads, list):
            msg = f"'payloads' must be a list, got {type(raw_payloads).__name__}"
            raise ValueError(msg)

        payloads: list[AttackPayload] = []
        for idx, entry in enumerate(raw_payloads):
            if not isinstance(entry, dict):
                msg = f"Payload at index {idx} must be a mapping, got {type(entry).__name__}"
                raise ValueError(msg)

            merged = _merge_export_metadata({**module_defaults, **entry})
            if "messages" not in merged and "prompt" in merged:
                merged["messages"] = [
                    {"role": "user", "content": str(merged["prompt"])},
                ]
            merged.pop("prompt", None)
            if "attack_module" not in merged:
                merged["attack_module"] = self.name
            if "owasp_id" not in merged:
                merged["owasp_id"] = self.owasp_id
            if "atlas_technique" not in merged:
                merged["atlas_technique"] = self.atlas_technique
            if "category" not in merged:
                merged["category"] = self.category
            if "severity" not in merged:
                merged["severity"] = self.default_severity
            try:
                payloads.append(AttackPayload(**merged))
            except ValidationError as exc:
                payload_id = entry.get("id", f"index-{idx}")
                msg = f"Invalid payload '{payload_id}' in {self.name}.yaml: {exc}"
                raise ValueError(msg) from exc

        return payloads


    def _filter_payloads(
        self,
        payloads: list[AttackPayload],
        target_config: dict[str, Any],
    ) -> list[AttackPayload]:
        """Default filter: keep payloads with satisfied tool requirements."""
        available_tools = self._extract_available_tools(target_config)
        if not available_tools:
            return [p for p in payloads if p.target_tools is None]

        filtered: list[AttackPayload] = []
        for payload in payloads:
            if payload.target_tools is None:
                filtered.append(payload)
                continue
            required = self._normalize_tool_names(payload.target_tools)
            if required.issubset(available_tools):
                filtered.append(payload)
        return filtered

    def _extract_available_tools(self, target_config: dict[str, Any]) -> frozenset[str]:
        servers = target_config.get("mcp_servers", [])
        if not isinstance(servers, list):
            return frozenset()
        available = self._normalize_tool_names(servers)
        security = target_config.get("security", {})
        if isinstance(security, dict) and not bool(security.get("code_exec_enabled", True)):
            available.discard("code_exec")
        return frozenset(available)

    def _normalize_tool_names(self, names: list[str]) -> set[str]:
        out: set[str] = set()
        for name in names:
            lowered = str(name).strip().lower()
            if not lowered:
                continue
            out.add(_TOOL_ALIASES.get(lowered, lowered))
        return out

    def _prepare_payload_for_run(
        self,
        payload: AttackPayload,
        agent: AgentInterface,
    ) -> AttackPayload:
        """Inject context through the requested method before agent.run()."""
        context = payload.injected_context
        if not context:
            return payload

        metadata = payload.metadata if isinstance(payload.metadata, dict) else {}
        method_raw = metadata.get("injection_method", "rag")
        method = str(method_raw).strip().lower()
        if method not in {"rag", "memory", "tool_output"}:
            method = "rag"

        agent.inject_context(context, method=method)
        return payload.model_copy(update={"injected_context": None})

def _merge_export_metadata(merged: dict[str, Any]) -> dict[str, Any]:
    """Move dataset-export fields into runtime metadata before Pydantic validation."""
    metadata = dict(merged.get("metadata") or {})
    for export_key, metadata_key in _EXPORT_METADATA_KEYS.items():
        if export_key not in merged:
            continue
        value = merged.pop(export_key)
        metadata.setdefault(metadata_key, value)
    merged["metadata"] = metadata
    return merged
