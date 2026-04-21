"""Promote nested payload metadata fields to top-level Phase 5 export fields.

This script preserves existing YAML comments and quoting where possible. It uses
PyYAML only to read payload metadata, then patches each payload block by inserting
or replacing the export fields near the top of that block.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

MODULES = (
    "asi_dynamic_cloak",
    "asi03_identity_privilege",
    "asi_semantic_manip",
    "llm01_crosslingual",
    "asi07_inter_agent",
    "asi_hitl",
    "asi09_human_trust",
)
PAYLOAD_DIR = Path("datasets/payloads")
_EXPORT_KEYS = ("technique_tag", "is_negative_control", "attack_family", "version")
_PAYLOAD_ID_RE = re.compile(r'^  - id:\s*(.+?)\s*$')
_TOP_LEVEL_EXPORT_RE = re.compile(r'^    (technique_tag|is_negative_control|attack_family|version):')


def _metadata(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("metadata")
    return value if isinstance(value, dict) else {}


def _field_values(payload: dict[str, Any], module: str) -> dict[str, Any]:
    metadata = _metadata(payload)
    technique = payload.get("technique_tag") or metadata.get("technique_tag") or metadata.get("technique")
    negative = payload.get("is_negative_control")
    if negative is None:
        negative = metadata.get("is_negative_control", metadata.get("negative_control", False))
    return {
        "technique_tag": str(technique) if technique else None,
        "is_negative_control": bool(negative),
        "attack_family": module,
        "version": "v2",
    }


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return json.dumps(str(value), ensure_ascii=False)


def _parse_payload_id(line: str) -> str | None:
    match = _PAYLOAD_ID_RE.match(line)
    if not match:
        return None
    value = yaml.safe_load(match.group(1))
    return str(value) if value is not None else None


def _payload_blocks(lines: list[str]) -> list[tuple[int, int, str]]:
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        payload_id = _parse_payload_id(line)
        if payload_id is not None:
            starts.append((index, payload_id))

    blocks: list[tuple[int, int, str]] = []
    for pos, (start, payload_id) in enumerate(starts):
        end = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        blocks.append((start, end, payload_id))
    return blocks


def _insert_index(block: list[str]) -> int:
    for index, line in enumerate(block):
        if line.startswith("    metadata:"):
            return index
    for index, line in enumerate(block):
        if line.startswith("    severity:"):
            return index + 1
    return 1


def _normalize_text(text: str, field_map: dict[str, dict[str, Any]]) -> tuple[str, int]:
    lines = text.splitlines()
    blocks = _payload_blocks(lines)
    changed = 0

    for start, end, payload_id in reversed(blocks):
        fields = field_map.get(payload_id)
        if not fields:
            continue
        block = [line for line in lines[start:end] if not _TOP_LEVEL_EXPORT_RE.match(line)]
        export_lines = [
            f"    {key}: {_yaml_scalar(fields[key])}"
            for key in _EXPORT_KEYS
            if fields.get(key) is not None
        ]
        insert_at = _insert_index(block)
        new_block = block[:insert_at] + export_lines + block[insert_at:]
        if new_block != lines[start:end]:
            changed += 1
            lines[start:end] = new_block

    return "\n".join(lines) + "\n", changed


def normalize_file(path: Path, module: str) -> tuple[int, int]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected YAML mapping")
    payloads = data.get("payloads")
    if not isinstance(payloads, list):
        raise ValueError(f"{path}: expected payloads list")

    field_map = {
        str(payload["id"]): _field_values(payload, module)
        for payload in payloads
        if isinstance(payload, dict) and payload.get("id")
    }
    updated, changed = _normalize_text(path.read_text(encoding="utf-8"), field_map)
    path.write_text(updated, encoding="utf-8")
    return changed, len(payloads)


def main() -> int:
    for module in MODULES:
        path = PAYLOAD_DIR / f"{module}.yaml"
        if not path.exists():
            print(f"SKIP {module}: file missing")
            continue
        changed, total = normalize_file(path, module)
        print(f"OK   {module}: normalized {changed}/{total} payloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
