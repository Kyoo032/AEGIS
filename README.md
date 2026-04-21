# AEGIS — Agentic Exploit & Guardrail Investigation Suite

Security testing framework for agentic AI systems. AEGIS runs adversarial payloads against a local or configured target agent, scores exploit success, and emits structured reports for review.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-751%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-88.8%25-brightgreen)]()

## Current validated snapshot

Validated on April 21, 2026 against a single local Ollama model using [config.local_single_qwen.yaml](/home/kyo/AEGIS/aegis/config.local_single_qwen.yaml):

- Target model: `qwen3.5:0.8b`
- Provider path: Ollama `POST /api/chat` with `think: false`
- Attack modules: 15
- Payloads: 191
- Fresh live artifact: [baseline.json](/home/kyo/AEGIS/reports/baseline.json)
- Full test gate: `751 passed`, `88.80%` coverage

Overall baseline ASR from the fresh local run: `144 / 191 = 75.39%`.

## Baseline findings

| Module | Category | ASR |
|---|---|---:|
| `asi04_supply_chain` | Supply Chain Vulnerabilities | `10/10` `1.0000` |
| `asi02_tool_misuse` | Tool Misuse & Exploitation | `9/10` `0.9000` |
| `asi_semantic_manip` | Semantic Manipulation | `14/16` `0.8750` |
| `asi_hitl` | Human-in-the-Loop Approval Failures | `11/13` `0.8462` |
| `asi03_identity_privilege` | Identity and Privilege Abuse | `10/12` `0.8333` |
| `asi_dynamic_cloak` | Dynamic Cloaking | `10/12` `0.8333` |
| `asi09_human_trust` | Human Trust Exploitation | `10/12` `0.8333` |
| `asi01_goal_hijack` | Agent Goal Hijacking | `8/10` `0.8000` |
| `mcp06_cmd_injection` | Command Injection via MCP | `8/10` `0.8000` |
| `asi07_inter_agent` | Inter-Agent Trust Boundary | `11/14` `0.7857` |
| `llm01_crosslingual` | Cross-Lingual Prompt Injection | `19/26` `0.7308` |
| `asi05_code_exec` | Unexpected Code Execution | `7/10` `0.7000` |
| `asi06_memory_poison` | Memory & Context Poisoning | `7/13` `0.5385` |
| `llm02_data_disclosure` | Sensitive Information Disclosure | `5/10` `0.5000` |
| `llm01_prompt_inject` | Prompt Injection | `5/13` `0.3846` |

The fresh local run materially changes the old core-only picture: prompt injection is no longer the dominant story; supply chain, semantic manipulation, approval abuse, identity abuse, and dynamic cloaking are.

## Why the local Ollama path matters

AEGIS now uses Ollama chat requests for Qwen-backed local execution because current Qwen thinking models can return an empty `response` on `/api/generate` while filling only the `thinking` field. The validated single-model path in [config.local_single_qwen.yaml](/home/kyo/AEGIS/aegis/config.local_single_qwen.yaml) keeps the run realistic for low-VRAM machines:

- one local model at a time
- target and judge on the same model
- no separate judge model required
- no extra server instances

## Quick start

### Low-VRAM local path

```bash
git clone https://github.com/Kyoo032/AEGIS.git
cd AEGIS
uv sync --dev

ollama pull qwen3.5:0.8b

uv run aegis scan --config aegis/config.local_single_qwen.yaml --format json --output reports
```

### Default repo path

The repo still ships the broader default config in [config.yaml](/home/kyo/AEGIS/aegis/config.yaml). Use that when you want the standard multi-profile setup rather than the validated low-VRAM local override.

```bash
uv run aegis scan
uv run aegis attack --module asi_dynamic_cloak
uv run aegis defend --defense input_validator
uv run aegis matrix
uv run aegis report --format html
```

## Attack surface

AEGIS currently includes 15 active attack modules:

| Module | Category |
|---|---|
| `asi01_goal_hijack` | Agent Goal Hijacking |
| `asi02_tool_misuse` | Tool Misuse & Exploitation |
| `asi03_identity_privilege` | Identity and Privilege Abuse |
| `asi04_supply_chain` | Supply Chain Vulnerabilities |
| `asi05_code_exec` | Unexpected Code Execution |
| `asi06_memory_poison` | Memory & Context Poisoning |
| `asi07_inter_agent` | Inter-Agent Trust Boundary |
| `asi09_human_trust` | Human Trust Exploitation |
| `asi_dynamic_cloak` | Dynamic Cloaking |
| `asi_hitl` | Human-in-the-Loop Approval Failures |
| `asi_semantic_manip` | Semantic Manipulation |
| `llm01_crosslingual` | Cross-Lingual Prompt Injection |
| `llm01_prompt_inject` | Prompt Injection |
| `llm02_data_disclosure` | Sensitive Information Disclosure |
| `mcp06_cmd_injection` | Command Injection via MCP |

## Defenses

AEGIS ships five defense modules:

| Defense | Purpose |
|---|---|
| `input_validator` | Input sanitization and injection blocking |
| `output_filter` | Response filtering and redaction |
| `tool_boundary` | Tool parameter validation and boundary checks |
| `mcp_integrity` | MCP manifest integrity and drift checks |
| `permission_enforcer` | Least-privilege tool policy enforcement |

The most recent defense-matrix interpretation is documented in [DEFENSE_EVALUATION.md](/home/kyo/AEGIS/docs/DEFENSE_EVALUATION.md). The April 21 local run in this README is a fresh baseline-only live scan, not a new full defense matrix.

## Testing

Validated commands:

```bash
uv run ruff check .
uv run --extra dashboard pytest -s --cov=aegis --cov-report=term-missing --cov-fail-under=80
uv run aegis scan --config aegis/config.local_single_qwen.yaml --format json --output reports
```

Notes:

- The dashboard tests need the `dashboard` extra because they import `plotly`, `pandas`, and `streamlit`.
- CLI runs return exit code `2` when vulnerabilities are found.
- Generated run artifacts under `reports/` are intentionally local outputs, not all of them are tracked in Git.

## Documentation

| Document | Description |
|---|---|
| [FINDINGS.md](/home/kyo/AEGIS/docs/FINDINGS.md) | Fresh baseline results and local-run observations |
| [METHODOLOGY.md](/home/kyo/AEGIS/docs/METHODOLOGY.md) | Scoring, local execution path, and reproducibility notes |
| [DEFENSE_EVALUATION.md](/home/kyo/AEGIS/docs/DEFENSE_EVALUATION.md) | Defense-matrix interpretation and current limits |
| [CHANGELOG.md](/home/kyo/AEGIS/CHANGELOG.md) | Release history and current development notes |

## License

[MIT](LICENSE)
