<div align="center">

# AEGIS

### Agentic Exploit & Guardrail Investigation Suite

*An adversarial security testing framework for agentic AI systems.*

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-751%20passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-88.8%25-brightgreen)]()
[![Attack Modules](https://img.shields.io/badge/attacks-15-orange)]()
[![Payloads](https://img.shields.io/badge/payloads-191-red)]()

[Quick Start](#-quick-start) · [How It Works](#-how-it-works) · [Attack Surface](#-attack-surface) · [Integrate Your Model](#-integrate-your-own-model) · [Docs](#-documentation)

</div>

---

## What is AEGIS?

AEGIS is a **red-team framework for LLM agents**. It fires adversarial payloads at a target model, watches how the agent reacts, scores the outcome with both deterministic rules and an LLM judge, and emits a structured report you can audit.

It is designed for the reality of modern agentic systems: tool use, MCP servers, RAG, multi-turn conversations, and the gap between "the model refuses" and "the agent still does the dangerous thing."

> **Latest validation:** `qwen3.5:0.8b` via Ollama — 191 payloads, **75.39% overall ASR** (Attack Success Rate). See [baseline.json](reports/baseline.json).

---

## Highlights

- **15 attack modules** covering goal hijack, tool misuse, supply chain, code exec, memory poisoning, MCP injection, cross-lingual prompts, and more.
- **5 defense modules** for layered hardening — input validation, output filtering, tool boundaries, MCP integrity, permission enforcement.
- **Dual-scorer evaluation:** deterministic rule-based scoring + LLM-judge confirmation.
- **Low-VRAM friendly:** validated path runs one model on consumer hardware via Ollama.
- **Pluggable providers:** Ollama, Hugging Face, or offline fixtures.
- **Structured reports:** JSON + HTML, with optional Streamlit dashboard.
- **CI-ready:** exit code `2` when vulnerabilities are found, so pipelines can fail loudly.

---

## 🚀 Quick Start

### Prerequisites

- Python **3.11+**
- [`uv`](https://github.com/astral-sh/uv) package manager
- [`ollama`](https://ollama.com) running locally (for the validated path)

### Install

```bash
git clone https://github.com/Kyoo032/AEGIS.git
cd AEGIS
uv sync --dev
```

### Run the validated low-VRAM scan

```bash
# 1. Pull the test model
ollama pull qwen3.5:0.8b

# 2. Launch the full baseline scan (15 modules × ~13 payloads)
uv run aegis scan \
    --config aegis/config.local_single_qwen.yaml \
    --format json \
    --output reports
```

The run writes a timestamped artifact into `reports/` and exits with code `2` if any payload succeeded.

### Other commands

```bash
uv run aegis scan                               # Full scan using default config
uv run aegis attack --module asi_dynamic_cloak  # Single attack module
uv run aegis defend --defense input_validator   # Scan with one defense active
uv run aegis matrix                             # Baseline vs. defense matrix
uv run aegis report --format html               # Render HTML report
```

---

## 🧩 How It Works

```
┌──────────────┐   ┌─────────────┐   ┌──────────────┐   ┌──────────────┐
│  Attack      │──▶│  Testbed    │──▶│  Target      │──▶│  Evaluator   │
│  Modules     │   │  Agent      │   │  LLM         │   │  (rule+judge)│
│  (payloads)  │   │  (MCP/RAG)  │   │  (your model)│   │              │
└──────────────┘   └─────────────┘   └──────────────┘   └──────┬───────┘
                                                               │
                                                               ▼
                                                        ┌──────────────┐
                                                        │  Report      │
                                                        │  JSON / HTML │
                                                        └──────────────┘
```

1. **Attack modules** generate adversarial payloads for a specific vulnerability class (e.g. prompt injection, tool misuse).
2. The **testbed agent** wraps your target model with configurable MCP servers, RAG, memory, and safety profiles (`default` / `hardened` / `minimal`).
3. Your **target LLM** produces a response.
4. The **evaluator** scores it with deterministic rules *and* an LLM judge. A payload is flagged successful only when both signals agree.
5. Optional **defenses** sit between attacker and agent, letting you measure the blast-radius reduction of each guardrail.
6. **Reports** are written as machine-readable JSON and human-readable HTML.

### Scoring model

| Scorer | What it checks |
|---|---|
| `rule_based` | Deterministic heuristics (forbidden actions, string leaks, tool-call signatures) |
| `llm_judge` | An LLM re-reads the transcript and judges whether the attacker's goal was met |

Successful = flagged by **both** scorers with confidence above the threshold.

---

## 🎯 Attack Surface

<details open>
<summary><b>15 active modules — click for baseline ASR against <code>qwen3.5:0.8b</code></b></summary>

| Module | Category | ASR (baseline) |
|---|---|---:|
| `asi04_supply_chain` | Supply Chain Vulnerabilities | **10/10 — 100.0%** |
| `asi02_tool_misuse` | Tool Misuse & Exploitation | **9/10 — 90.0%** |
| `asi_semantic_manip` | Semantic Manipulation | **14/16 — 87.5%** |
| `asi_hitl` | Human-in-the-Loop Approval Failures | **11/13 — 84.6%** |
| `asi03_identity_privilege` | Identity and Privilege Abuse | **10/12 — 83.3%** |
| `asi_dynamic_cloak` | Dynamic Cloaking | **10/12 — 83.3%** |
| `asi09_human_trust` | Human Trust Exploitation | **10/12 — 83.3%** |
| `asi01_goal_hijack` | Agent Goal Hijacking | **8/10 — 80.0%** |
| `mcp06_cmd_injection` | Command Injection via MCP | **8/10 — 80.0%** |
| `asi07_inter_agent` | Inter-Agent Trust Boundary | **11/14 — 78.6%** |
| `llm01_crosslingual` | Cross-Lingual Prompt Injection | **19/26 — 73.1%** |
| `asi05_code_exec` | Unexpected Code Execution | **7/10 — 70.0%** |
| `asi06_memory_poison` | Memory & Context Poisoning | **7/13 — 53.9%** |
| `llm02_data_disclosure` | Sensitive Information Disclosure | **5/10 — 50.0%** |
| `llm01_prompt_inject` | Prompt Injection | **5/13 — 38.5%** |

> **Key insight:** classic prompt-injection is the *least* effective vector against this target. The biggest risks are **supply chain, tool misuse, semantic manipulation, and approval-failure** patterns — the places where the agent's *scaffolding* is exploited, not its text prompt.

</details>

---

## 🛡️ Defenses

| Defense | Purpose |
|---|---|
| `input_validator` | Input sanitization and injection blocking |
| `output_filter` | Response filtering and redaction |
| `tool_boundary` | Tool parameter validation and boundary checks |
| `mcp_integrity` | MCP manifest integrity and drift detection |
| `permission_enforcer` | Least-privilege tool policy enforcement |

Run defenses individually (`aegis defend --defense <name>`) or as layered stacks declared under `defenses.layered_combinations` in your config.

The latest defense-matrix analysis lives in [DEFENSE_EVALUATION.md](docs/DEFENSE_EVALUATION.md).

---

## 🔌 Integrate Your Own Model

AEGIS accepts any model exposed through the supported providers. The fastest path is to point Ollama at your model and swap the model name in a config file.

### Option A — Ollama (recommended, local)

```bash
ollama pull <your-model>:<tag>
```

Create `aegis/config.my_model.yaml`:

```yaml
testbed:
  model: "<your-model>:<tag>"
  fallback_model: "<your-model>:<tag>"
  provider:
    mode: "ollama"
    ollama_base_url: "http://localhost:11434"
    ollama_generate_timeout_seconds: 120
    ollama_num_predict: 128
    require_external: true
  agent_profile: "default"

evaluation:
  scorers: [rule_based, llm_judge]
  judge_model: "<your-model>:<tag>"   # or a separate, stronger judge
  judge_timeout_seconds: 180

reporting:
  formats: ["json", "html"]
  output_dir: "./reports"
```

Run it:

```bash
uv run aegis scan --config aegis/config.my_model.yaml
```

### Option B — Hugging Face

```yaml
testbed:
  provider:
    mode: "huggingface"
    hf_model: "meta-llama/Llama-3.2-3B-Instruct"
    hf_token_env: "HF_TOKEN"
```

Then export your token: `export HF_TOKEN=hf_...`

### Option C — Hosted APIs / custom providers

Implement the provider interface in [aegis/interfaces](aegis/interfaces) and wire it into [aegis/testbed](aegis/testbed). The orchestrator is provider-agnostic — it only needs a callable that takes messages and returns a completion.

### Separate judge model

Stronger judge + weaker target gives cleaner signal. In your config:

```yaml
evaluation:
  judge_model: "llama3.1:8b"   # bigger judge
testbed:
  model: "qwen3.5:0.8b"        # smaller target under test
```

### Why the low-VRAM single-model path exists

Current Qwen "thinking" models can return an empty `response` on Ollama's `/api/generate` while filling only the `thinking` field. AEGIS uses `/api/chat` with `think: false` and reuses the same small model as both target and judge so you can run the full suite on a 4 GB GPU.

---

## 🧪 Testing

```bash
uv run ruff check .
uv run --extra dashboard pytest -s --cov=aegis --cov-report=term-missing --cov-fail-under=80
uv run aegis scan --config aegis/config.local_single_qwen.yaml --format json --output reports
```

- Dashboard tests require the `dashboard` extra (`plotly`, `pandas`, `streamlit`).
- CLI exit codes: `0` clean · `1` runtime error · `2` vulnerabilities found.
- Artifacts in `reports/` are intentionally local; not all are tracked in Git.

---

## 📂 Repository Layout

```
aegis/
├── attacks/         # 15 attack modules (payload generators)
├── defenses/        # 5 guardrail modules
├── evaluation/      # rule-based + LLM-judge scorers
├── testbed/         # agent harness, MCP servers, RAG, memory
├── scoring/         # ASR computation and aggregation
├── reporting/       # JSON / HTML / matrix renderers
├── interfaces/      # provider + tool contracts
├── cli.py           # `aegis` CLI entry point
├── orchestrator.py  # scan / attack / defend / matrix pipelines
├── config.yaml                      # default multi-profile config
└── config.local_single_qwen.yaml    # validated low-VRAM config

dashboard/           # Streamlit dashboard (optional)
datasets/            # fixtures, KB corpora, payload seeds
docs/                # methodology, findings, evaluation reports
reports/             # generated scan artifacts (local)
tests/               # 751 tests, 88.8% coverage
```

---

## 📚 Documentation

| Document | Description |
|---|---|
| [FINDINGS.md](docs/FINDINGS.md) | Fresh baseline results and local-run observations |
| [METHODOLOGY.md](docs/METHODOLOGY.md) | Scoring, local execution path, reproducibility notes |
| [DEFENSE_EVALUATION.md](docs/DEFENSE_EVALUATION.md) | Defense-matrix interpretation and current limits |
| [PROBE_CATALOG_REVIEW.md](docs/PROBE_CATALOG_REVIEW.md) | Per-module payload catalog review |
| [CHANGELOG.md](CHANGELOG.md) | Release history and development notes |
| [TASK_PROMPTS.md](TASK_PROMPTS.md) | Benign task prompts used for agent behavior |

---

## 🤝 Contributing

Issues and pull requests welcome — especially new attack modules and defense strategies. Please:

1. Run `uv run ruff check .` and `pytest` before submitting.
2. Keep coverage at or above 80%.
3. Include a payload rationale and expected scoring signal for new attacks.

---

## 📜 License

Released under the [MIT License](LICENSE). AEGIS is a research and defensive-testing tool. Only run it against systems you own or have explicit authorization to test.
