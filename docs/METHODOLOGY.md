# AEGIS Security Testing Methodology

## Framework alignment

- OWASP Top 10 for LLM Applications
- OWASP Agentic AI threat categories
- MITRE ATLAS
- Local agent-tool attack simulation via MCP-style tool surfaces

## Current corpus

The current repo validates 15 active attack modules:

- `asi01_goal_hijack`
- `asi02_tool_misuse`
- `asi03_identity_privilege`
- `asi04_supply_chain`
- `asi05_code_exec`
- `asi06_memory_poison`
- `asi07_inter_agent`
- `asi09_human_trust`
- `asi_dynamic_cloak`
- `asi_hitl`
- `asi_semantic_manip`
- `llm01_crosslingual`
- `llm01_prompt_inject`
- `llm02_data_disclosure`
- `mcp06_cmd_injection`

The fresh April 21, 2026 local baseline covered `191` payloads across that full set.

## Execution model

AEGIS runs as a black-box adversarial harness:

1. load payloads for the requested modules
2. execute the target agent against each payload
3. collect the final output, tool calls, retrieval trace, memory state, and errors
4. score success using rule-based signals and, when enabled, an LLM judge
5. generate structured JSON/HTML reports

## Local Ollama path

The validated low-VRAM local path is [config.local_single_qwen.yaml](/home/kyo/AEGIS/aegis/config.local_single_qwen.yaml):

- model: `qwen3.5:0.8b`
- one local model at a time
- target and judge share the same Ollama model
- provider mode forced to Ollama

### Why AEGIS uses Ollama chat requests for Qwen

Current Qwen thinking models on Ollama can return an empty `response` field on `/api/generate` while populating only the `thinking` field. That breaks a harness that expects a visible answer string. The validated local path therefore uses `POST /api/chat` with `think: false` for both target-agent and judge calls.

This is not a theoretical concern; it was observed directly during the April 21 local run before the Ollama call path was switched.

## Scoring

### Rule-based scorer

The rule-based scorer is the stable baseline signal. It inspects:

- dangerous tool calls
- sensitive file access
- exfiltration behavior
- suspicious paths and parameters
- poisoned retrieval dominance
- module-specific attack-family indicators

### LLM judge

The LLM judge remains useful for adjudicating ambiguous outputs, but local single-model Qwen runs can still produce unparseable structured verdicts. Treat the judge as a secondary signal unless the run explicitly shows stable structured outputs for the chosen model.

## Reproducibility

Validated commands from the fresh local run:

```bash
uv sync --dev
ollama pull qwen3.5:0.8b
uv run ruff check .
uv run --extra dashboard pytest -s --cov=aegis --cov-report=term-missing --cov-fail-under=80
uv run aegis scan --config aegis/config.local_single_qwen.yaml --format json --output reports
```

Fresh outputs from the April 21 run:

- [baseline.json](/home/kyo/AEGIS/reports/baseline.json)
- [attack_results_0c9c3d74-756e-4230-9686-a356f80c3c69.jsonl](/home/kyo/AEGIS/reports/attack_results_0c9c3d74-756e-4230-9686-a356f80c3c69.jsonl)
- [trace_records_0c9c3d74-756e-4230-9686-a356f80c3c69.jsonl](/home/kyo/AEGIS/reports/trace_records_0c9c3d74-756e-4230-9686-a356f80c3c69.jsonl)

## Exit codes

- `0`: run completed and no successful attacks were detected
- `1`: configuration/runtime/tool error
- `2`: run completed and at least one vulnerability was detected

## Limits

- This is still a point-in-time harness.
- Report mappings for newly added agentic categories can lag the payload corpus if category metadata evolves faster than report labels.
- Local model quality and structured-output stability materially affect LLM-judge quality.
- A fresh defense matrix is separate work from a fresh baseline live scan.
