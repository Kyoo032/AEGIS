# Changelog

## v2.0.0 - 2026-04-21

This entry captures the AEGIS v2 release packaging state after the Phase 5 evaluation and reporting pass plus the lightweight-by-default cleanup.

### Added

- Seven v2 attack modules:
  - `asi03_identity_privilege`
  - `asi07_inter_agent`
  - `asi09_human_trust`
  - `asi_dynamic_cloak`
  - `asi_hitl`
  - `asi_semantic_manip`
  - `llm01_crosslingual`
- Release-facing v2 payload exports under `datasets/payloads/`
- Per-module Phase 5 rubric calibration blocks for all seven v2 modules
- Deterministic v2 matrix config at `aegis/config.phase5b_v2_matrix.yaml`
- Phase 5 release-readiness regression coverage in `tests/test_attacks/test_phase5_release_readiness.py`
- Lightweight-by-default runtime: `aegis/config.minimal.yaml` smoke config and `orchestration.max_probes_per_module` cap for seconds-not-minutes cloud / BYO-model runs
- In-tree Phase 5 matrix artifact: `reports/day89_defense_matrix_20260420T132439Z.json` is now allowlisted in `.gitignore` so reviewers can inspect the cited evidence from a fresh clone

### Changed

- Report schema now accepts hyphenated v2 OWASP IDs such as `ASI-DYNAMIC-CLOAK`
- `scripts/normalize_payload_metadata.py` now normalizes the full v2 release lane metadata
- `docs/DEFENSE_EVALUATION.md` now reflects the fresh v2 matrix artifact and module-level ASR/FPR
- `README.md`, `docs/METHODOLOGY.md`, and `docs/FINDINGS.md` now describe the v2 release lane instead of only the historical core lane
- Default `aegis/config.yaml` now ships with `testbed.provider.mode: offline` and `evaluation.scorers: [rule_based]` so a fresh install runs without Ollama / HuggingFace. Flip `mode` and uncomment `llm_judge` to exercise a live provider.
- `tests/test_orchestrator.py` is now part of the default pytest gate (previously `--ignore`'d); covers baseline runs, matrix generation, JSONL attack output, and scorer round-trips.
- Package version bumped to `2.0.0` in `pyproject.toml` to match the release.

### Removed

- Draft `datasets/payloads/llm01_crosslingual_draft.yaml` no longer ships in the public payloads directory; the release-facing `llm01_crosslingual.yaml` remains the single source of truth.

### v2 Evaluation Snapshot

- Matrix artifact: `reports/day89_defense_matrix_20260420T132439Z.json`
- Scope: `105` probes across `7` v2 modules
- Baseline ASR: `0.8286`
- Negative-control FPR: `0.0000` across scenarios and baseline modules
- Only `input_validator` materially reduced aggregate ASR in the current deterministic v2 matrix

### ASI03 Migration Notes

- The old ASI03 training-data-poisoning placeholder path is no longer the shipped ASI03 release lane.
- AEGIS v2 uses `asi03_identity_privilege` as the active ASI03 track.
- The deprecated implementation remains in `aegis/attacks/_deprecated/asi03_training_data_poison.py` for migration history only.

### Testing and Verification

- Latest full test gate: `773 passed` (now includes `tests/test_orchestrator.py`)
- Coverage: `89.01%`
- Targeted Phase 5 reduced gate:
  - `ruff check .`
  - `git diff --check`
  - targeted pytest on config, schema, and Phase 5 release-readiness tests
  - schema validation for the v2 matrix artifact
  - schema validation for all seven v2 smoke reports

### Deferred Scope

The following are intentionally not claimed as shipped v2 coverage:

- `ASI08` cascading failures
- `ASI10` rogue agents

The following publication polish is still tracked after this changelog entry:

- replace or explicitly defer remaining synthetic HITL and multilingual wording in the product-improvement pass

---

## v1.0.0 - 2026-02-26

Initial release of AEGIS with the historical core attack lane.

### Attack Modules

- `llm01_prompt_inject`
- `llm02_data_disclosure`
- `asi01_goal_hijack`
- `asi02_tool_misuse`
- `asi04_supply_chain`
- `asi05_code_exec`
- `asi06_memory_poison`
- `mcp06_cmd_injection`

### Defense Modules

- `input_validator`
- `output_filter`
- `tool_boundary`
- `mcp_integrity`
- `permission_enforcer`

### Capabilities

- baseline scan, single-module attack, single-defense run, matrix run, and report rendering
- rule-based scoring plus optional judge-backed scoring
- HTML and JSON report generation
- CI lint, test, and schema validation gates
