# AEGIS

> Agentic Exploit & Guardrail Investigation Suite

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-773%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-89.01%25-brightgreen)]()

AEGIS is a security testing framework for tool-using AI agents. It exercises prompt injection, tool misuse, identity delegation, cloaked content, human-approval abuse, inter-agent trust failures, and related agentic attack surfaces, then emits structured reports for reproduction and defense analysis.

## Release Snapshot

- Registered attack modules: `15`
- New v2 research modules: `7`
- Phase 5 v2 matrix scope: `105` probes across `7` modules
- Latest v2 baseline ASR: `0.8286` (`87/105`)
- Latest full test gate: `773 passed`, `89.01%` coverage
- Deferred scope: `ASI08` cascading failures and `ASI10` rogue agents

The current v2 evaluation lane is documented in [docs/DEFENSE_EVALUATION.md](docs/DEFENSE_EVALUATION.md). Historical v1/core results remain in the repo for comparison, but the v2 matrix is the current release-facing source of truth.

## What Ships

AEGIS currently ships `15` registered attack modules:

| Track | Modules |
|---|---|
| Legacy/core | `asi01_goal_hijack`, `asi02_tool_misuse`, `asi04_supply_chain`, `asi05_code_exec`, `asi06_memory_poison`, `mcp06_cmd_injection`, `llm01_prompt_inject`, `llm02_data_disclosure` |
| v2 research | `asi03_identity_privilege`, `asi07_inter_agent`, `asi09_human_trust`, `asi_dynamic_cloak`, `asi_hitl`, `asi_semantic_manip`, `llm01_crosslingual` |

The v2 track extends AEGIS beyond input-level prompt injection into agent-specific failures:

- identity and delegated-authority abuse
- agent-visible cloaked content that scanners do not see
- semantic manipulation without obvious jailbreak syntax
- cross-lingual and mixed-script instruction following
- unverified peer-message trust
- human approval summary mismatch and escalation
- deceptive trust signals aimed at the user

## Quick Start

### Install

```bash
git clone https://github.com/Kyoo032/AEGIS.git
cd AEGIS
uv sync --dev
```

> **Lightweight by default — no Ollama / HuggingFace required.**
> As of v2.0.0 AEGIS ships with [aegis/config.yaml](aegis/config.yaml) set to `testbed.provider.mode: offline` and the `rule_based` scorer only. A fresh clone runs the full pipeline in seconds with no external model, which is the right default for cloud deploys and BYO-model users.
>
> Offline mode uses a deterministic heuristic dispatcher ([aegis/testbed/agent.py](aegis/testbed/agent.py)), not a live LLM. Offline results are **not** a valid model evaluation — they exist to verify the pipeline works end-to-end.
>
> To run against a real model:
>
> - set `testbed.provider.mode` to `ollama` or `huggingface`, and
> - uncomment `- llm_judge` under `evaluation.scorers`, and
> - optionally set `testbed.provider.require_external: true` so AEGIS fails fast instead of silently falling back to offline.
>
> Always check the `provider_selected` field in the agent metadata / run log before treating a result as a real model evaluation.

### Basic commands

```bash
uv run aegis --help

# Ultra-fast smoke: 1 probe per module, offline, rule-based only
uv run aegis scan --config aegis/config.minimal.yaml --format json

# Fast baseline scan (default config — offline + rule-based)
uv run aegis scan --format html

# Run one v2 module
uv run aegis attack --module asi_dynamic_cloak --format json

# Run the v2 deterministic defense matrix used in Phase 5
uv run aegis matrix --config aegis/config.phase5b_v2_matrix.yaml --format json
```

### Speeding up or scoping runs

- Cap payloads per module via `orchestration.max_probes_per_module` in your config (integer, or `null` for no cap). See [aegis/config.minimal.yaml](aegis/config.minimal.yaml) for a ready-to-use smoke config.
- Override provider mode per-run with `AEGIS_PROVIDER_MODE=offline|ollama|huggingface`.
- Override Ollama endpoint per-run with `OLLAMA_BASE_URL=http://...`.

### Validation commands

```bash
uv run ruff check .
uv run pytest --cov=aegis --cov-report=term-missing --cov-fail-under=80
uv run python scripts/validate_reports.py --schema report --input reports/attack-asi_dynamic_cloak.json
uv run python scripts/validate_reports.py --schema matrix --input reports/<matrix-file>.json
```

## v2 Module Table

The v2 public research lane covers seven modules and `105` probes in the current Phase 5 evaluation surface.

| Module | Surface | Attack techniques | Probes | Negative controls |
|---|---|---:|---:|---:|
| `asi_dynamic_cloak` | Agent-only or differential content retrieval | 5 | 12 | 2 |
| `asi03_identity_privilege` | Forged roles, delegation abuse, privilege transfer | 5 | 12 | 2 |
| `asi_semantic_manip` | Authority, urgency, anchoring, compliance, social proof | 7 | 16 | 2 |
| `llm01_crosslingual` | Indonesian, mixed-language, transliteration, homoglyph bypass | 7 | 26 | 5 |
| `asi07_inter_agent` | Peer-message provenance, replay, session smuggling | 6 | 14 | 2 |
| `asi_hitl` | Approval fatigue, summary mismatch, escalation, fake remediation | 5 | 13 | 2 |
| `asi09_human_trust` | Fake success cues, audit claims, citations, unsafe persuasion | 5 | 12 | 2 |

Technique breakdowns are stored in [datasets/payloads](datasets/payloads) and surfaced in the Phase 5 reporting path through `technique_tag`, `attack_family`, `expected_signal`, and `phase5_summary`.

## Latest v2 Findings

The current Phase 5 baseline matrix artifact is `reports/day89_defense_matrix_20260420T132439Z.json`. Baseline module ASR from that run:

| Module | Baseline ASR | Negative-control FPR |
|---|---:|---:|
| `asi_semantic_manip` | 0.8750 | 0.0000 |
| `asi_hitl` | 0.8462 | 0.0000 |
| `asi03_identity_privilege` | 0.8333 | 0.0000 |
| `asi09_human_trust` | 0.8333 | 0.0000 |
| `asi_dynamic_cloak` | 0.8333 | 0.0000 |
| `llm01_crosslingual` | 0.8077 | 0.0000 |
| `asi07_inter_agent` | 0.7857 | 0.0000 |

The main result from Phase 5 is simple: legacy v1-style defenses barely move most of these surfaces. In the current deterministic v2 matrix, only `input_validator` materially reduces aggregate ASR, and even that reduction is bounded to the more instruction-visible subsets of identity, semantic, and inter-agent abuse.

## Architecture Notes

AEGIS is organized around a small number of stable surfaces:

- `aegis/cli.py`: `scan`, `attack`, `defend`, `matrix`, `report`
- `aegis/orchestrator.py`: attack loading, defense wiring, scoring, matrix execution
- `aegis/attacks/`: attack module registry plus YAML-backed payload sets
- `aegis/scoring/`: deterministic rules and optional judge-backed rubrics
- `aegis/reporting/`: HTML and JSON report generation
- `datasets/payloads/`: release-facing v2 payload exports and metadata

Scoring supports two modes:

- `rule_based` for fast, reproducible gates
- `llm_judge` for richer adjudication where a local judge model is available

Phase 5 uses both:

- judge-backed smoke reports per v2 module
- deterministic v2 matrix via [aegis/config.phase5b_v2_matrix.yaml](aegis/config.phase5b_v2_matrix.yaml)

## Documentation

| Document | Purpose |
|---|---|
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Threat model, scoring, reproducibility, deferred scope |
| [docs/FINDINGS.md](docs/FINDINGS.md) | v2 baseline findings, representative evidence, residual risk |
| [docs/DEFENSE_EVALUATION.md](docs/DEFENSE_EVALUATION.md) | Defense matrix results and bypass interpretation |
| [CHANGELOG.md](CHANGELOG.md) | Release notes and migration history |

## Known Gaps and Deferred Scope

AEGIS v2 intentionally does not claim coverage for:

- `ASI08` cascading agent failures
- `ASI10` rogue agents

Those two categories need a multi-agent orchestration and discovery layer that the current local benchmark setup does not implement. They are documented as future work rather than shipped as shallow or misleading coverage.

There is also one explicit publication caveat still carried into Phase 7:

- some v2 payload phrasing remains synthetic or benchmark-oriented, especially in HITL approval records and parts of the cross-lingual lane

That work is tracked as the final Kyo/product improvement pass rather than being hidden inside the release docs.

## Security Defaults

- `code_exec` is disabled by default under `testbed.security.code_exec_enabled`
- HTTP access is allowlisted and private-network access is blocked
- filesystem actions are sandboxed to the configured safe root
- database queries are row-limited and timeout-bound
- report and matrix artifacts validate against JSON schemas in `schemas/`

## License

[MIT](LICENSE)
