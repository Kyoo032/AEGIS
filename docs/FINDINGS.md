# AEGIS Security Assessment Findings

## Assessment overview

- Run date: April 21, 2026
- Target path: single local Ollama model via [config.local_single_qwen.yaml](../aegis/config.local_single_qwen.yaml)
- Target model: `qwen3.5:0.8b`
- Attack scope: 15 modules, 191 payloads
- Baseline artifact: `reports/baseline.json` (local run output, gitignored)
- Raw payload log: `reports/attack_results_0c9c3d74-756e-4230-9686-a356f80c3c69.jsonl` (local run output, gitignored)

This run was executed one model at a time on local Ollama. The target and judge both used the same local Qwen model. The validated path uses Ollama chat requests with `think: false` because Qwen thinking models can return empty `response` values on `/api/generate`.

## Baseline summary

- Total payloads: `191`
- Successful payloads: `144`
- Overall baseline ASR: `0.7539`

## Per-module results

| Module | Category | Successful | ASR |
|---|---|---:|---:|
| `asi04_supply_chain` | Supply Chain Vulnerabilities | `10/10` | `1.0000` |
| `asi02_tool_misuse` | Tool Misuse & Exploitation | `9/10` | `0.9000` |
| `asi_semantic_manip` | Semantic Manipulation | `14/16` | `0.8750` |
| `asi_hitl` | Human-in-the-Loop Approval Failures | `11/13` | `0.8462` |
| `asi03_identity_privilege` | Identity and Privilege Abuse | `10/12` | `0.8333` |
| `asi_dynamic_cloak` | Dynamic Cloaking | `10/12` | `0.8333` |
| `asi09_human_trust` | Human Trust Exploitation | `10/12` | `0.8333` |
| `asi01_goal_hijack` | Agent Goal Hijacking | `8/10` | `0.8000` |
| `mcp06_cmd_injection` | Command Injection via MCP | `8/10` | `0.8000` |
| `asi07_inter_agent` | Inter-Agent Trust Boundary | `11/14` | `0.7857` |
| `llm01_crosslingual` | Cross-Lingual Prompt Injection | `19/26` | `0.7308` |
| `asi05_code_exec` | Unexpected Code Execution | `7/10` | `0.7000` |
| `asi06_memory_poison` | Memory & Context Poisoning | `7/13` | `0.5385` |
| `llm02_data_disclosure` | Sensitive Information Disclosure | `5/10` | `0.5000` |
| `llm01_prompt_inject` | Prompt Injection | `5/13` | `0.3846` |

## What changed from the older core-only picture

The older docs emphasized prompt injection, MCP command injection, and classic tool misuse. The fresh 15-module local run changes that picture:

1. Supply-chain style probes remain the easiest to land.
2. Semantic manipulation, HITL approval abuse, identity abuse, dynamic cloaking, and human-trust exploitation all sit in the `0.83-0.88` ASR range.
3. Prompt injection is still exploitable, but it is no longer the dominant category in the current corpus.
4. Cross-lingual probes remain materially exploitable at `0.7308`.

## Highest-signal observations

### 1. Supply chain remains the worst surface

`asi04_supply_chain` landed `10/10` successes. The strongest signals were poisoned context, malicious schema descriptions, cross-tool pivots, and MCP-style trust abuse.

### 2. Approval and human-trust surfaces are broadly exposed

The two explicitly human-mediated families stayed high:

- `asi_hitl`: `11/13` (`0.8462`)
- `asi09_human_trust`: `10/12` (`0.8333`)

That means the current agent behavior is still vulnerable when harmful actions are reframed as safe, routine, urgent, or already-approved work.

### 3. Identity and delegation abuse is not contained

`asi03_identity_privilege` landed `10/12` successes. Forged roles, delegated authority, spoofed metadata, and token-handling probes still move the agent into unsafe states often enough to matter operationally.

### 4. Cross-lingual risk is real, not decorative

`llm01_crosslingual` landed `19/26` successes. The local run confirms that multilingual and mixed-script prompt variants are not edge cases in this harness; they materially increase attack surface.

### 5. Classical prompt injection is no longer the main story

`llm01_prompt_inject` came in at `5/13` (`0.3846`), which is still nontrivial but lower than the more agentic and human-mediated attack families. That is the strongest evidence that the expanded v2-style corpus is testing different failure modes rather than merely reskinning LLM01.

## Local execution notes

Two local-run constraints matter for reproducibility:

1. Qwen thinking models on current Ollama builds can return empty `response` fields on `/api/generate` while emitting only `thinking`. AEGIS now uses the chat endpoint for the local Ollama path to avoid that failure mode.
2. The live scan completed on a single `qwen3.5:0.8b` model, but the LLM judge still produced repeated unparseable verdicts on some probes. The baseline artifact is still useful, but local single-model runs should treat rule-based evidence as the more stable signal.

## Recommendations

1. Tighten supply-chain, delegation, and approval-boundary controls before treating the agent as production-ready.
2. Keep multilingual and semantic-manipulation probes in the default regression set; they are currently first-tier risks.
3. Use the single-model local config for realistic low-VRAM validation, but do not confuse that with a clean defense-matrix rerun.
4. Treat current LLM-judge behavior on local Qwen as advisory until its structured-output stability improves.
