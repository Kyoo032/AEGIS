"""Validate AEGIS matrix/report JSON artifacts against local JSON schemas."""
from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

from jsonschema import Draft202012Validator

_SCHEMA_MAP = {
    "matrix": Path("schemas/matrix_summary.schema.json"),
    "report": Path("schemas/security_report.schema.json"),
}


def _load_schema(schema_kind: str) -> dict:
    schema_path = _SCHEMA_MAP[schema_kind]
    with schema_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_inputs(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        matched = sorted(Path(path) for path in glob.glob(pattern))
        if matched:
            paths.extend(path for path in matched if path.is_file())
            continue
        direct = Path(pattern)
        if direct.is_file():
            paths.append(direct)
    deduped = sorted(set(paths))
    if not deduped:
        raise FileNotFoundError(
            f"No input files found for patterns: {patterns}"
        )
    return deduped


def validate_files(schema_kind: str, input_patterns: list[str]) -> int:
    schema = _load_schema(schema_kind)
    validator = Draft202012Validator(schema)

    inputs = _resolve_inputs(input_patterns)
    failures = 0
    for path in inputs:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)

        errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
        if not errors:
            print(f"OK  {path}")
            continue

        failures += 1
        print(f"FAIL {path}")
        for err in errors[:10]:
            loc = ".".join(str(part) for part in err.absolute_path) or "$"
            print(f"  - {loc}: {err.message}")

    if failures:
        print(f"Validation failed for {failures} file(s).")
        return 1

    print(f"Validated {len(inputs)} file(s) with schema '{schema_kind}'.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate report artifacts.")
    parser.add_argument(
        "--schema",
        choices=sorted(_SCHEMA_MAP),
        required=True,
        help="Schema kind to apply",
    )
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Input file path or glob (repeatable)",
    )

    args = parser.parse_args()
    return validate_files(schema_kind=args.schema, input_patterns=args.input)


if __name__ == "__main__":
    raise SystemExit(main())
