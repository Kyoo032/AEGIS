# AEGIS Security Assessment Findings

## Assessment Overview
- Date: February 24, 2026 (UTC)
- Target: Local-first AEGIS testbed (`qwen3:4b` target profile, config in `aegis/config.day7_core7.yaml`)
- Attack modules: `asi01_goal_hijack`, `asi02_tool_misuse`, `asi04_supply_chain`, `asi05_code_exec`, `asi06_memory_poison`, `mcp06_cmd_injection`, `llm01_prompt_inject`
- Defenses evaluated: `input_validator`, `output_filter`, `tool_boundary`, `mcp_integrity`, `permission_enforcer`, plus layered combinations

## Baseline Results Summary

| Attack Category | Baseline ASR | Highest Observed Severity |
|---|---:|---|
| ASI01 | 0.1000 (1/10) | Critical |
| ASI02 | 0.9000 (9/10) | Critical |
| ASI04 | 0.9000 (9/10) | Critical |
| ASI05 | 0.0000 (0/10) | Informational |
| ASI06 | 0.0000 (0/5) | Informational |
| MCP06 | 1.0000 (10/10) | Critical |
| LLM01 | 0.0000 (0/13) | Informational |

## Defense Effectiveness Summary

| Defense Scenario | Attack Scope | Baseline ASR | Defended ASR | Delta | Improvement % |
|---|---|---:|---:|---:|---:|
| `input_validator` | All core-7 | 0.4265 | 0.1471 | -0.2794 | 65.52% |
| `output_filter` | All core-7 | 0.4265 | 0.4265 | +0.0000 | 0.00% |
| `tool_boundary` | All core-7 | 0.4265 | 0.3529 | -0.0735 | 17.24% |
| `mcp_integrity` | All core-7 | 0.4265 | 0.4265 | +0.0000 | 0.00% |
| `permission_enforcer` | All core-7 | 0.4265 | 0.4265 | +0.0000 | 0.00% |
| `input_validator+output_filter+tool_boundary` | All core-7 | 0.4265 | 0.0882 | -0.3382 | 79.31% |
| `mcp_integrity+permission_enforcer` | All core-7 | 0.4265 | 0.4265 | +0.0000 | 0.00% |
| `input_validator+output_filter+tool_boundary+mcp_integrity+permission_enforcer` | All core-7 | 0.4265 | 0.0882 | -0.3382 | 79.31% |

## Key Findings

1. **High residual risk in tool-mediated categories (Critical)**
- OWASP mapping: `ASI02`, `ASI04`, `MCP06`
- Description: Tool misuse, supply-chain style scenarios, and MCP command injection produced the highest baseline success rates.
- Evidence: Baseline ASR values of `0.9000`, `0.9000`, and `1.0000` respectively.
- Defense impact: `input_validator` and `tool_boundary` reduced aggregate ASR; strongest reduction observed in layered configurations.
- Recommendation: enforce strict tool parameter policies and keep input validation enabled by default.

2. **Single-layer controls show uneven impact (High)**
- OWASP mapping: cross-category aggregate
- Description: `input_validator` materially reduced ASR while `output_filter`, `mcp_integrity`, and `permission_enforcer` showed no aggregate delta in this run.
- Evidence: matrix deltas from `reports/day89_defense_matrix_20260224T082257Z.json`.
- Defense impact: best single-defense improvement from `input_validator` (`-0.2794`).
- Recommendation: prioritize controls that alter attack preconditions, then tune output/integrity/permission policies for stricter operating modes.

3. **Layering materially improves posture (High)**
- OWASP mapping: cross-category aggregate
- Description: Layered defenses achieved the strongest reduction (`-0.3382`) and dropped ASR to `0.0882`.
- Evidence: layered rows in matrix summary.
- Defense impact: adding `mcp_integrity` and `permission_enforcer` to the strongest layer did not further reduce aggregate ASR in this data slice.
- Recommendation: deploy layered baseline (`input_validator+output_filter+tool_boundary`) as the operational default profile.

## Weakest Areas
- `MCP06` and `ASI02` remain highest-priority risk categories based on baseline exploitability.
- Residual risk after strongest layering indicates additional policy tightening is required for tool usage and post-tool validation.

## Recommendations (Prioritized)
1. **[Critical]** Enforce `input_validator+tool_boundary` as mandatory baseline defenses for production-like profiles.
2. **[High]** Tighten `permission_enforcer` to stricter policy modes and explicit cross-tool flow restrictions.
3. **[High]** Expand `mcp_integrity` checks to runtime manifest/tool-drift conditions used in adversarial scenarios.
4. **[Medium]** Add regression probes for categories with historically high ASR (`ASI02`, `ASI04`, `MCP06`) to CI/nightly tiers.

## Data Sources
- Matrix summary: `reports/day89_defense_matrix_20260224T082257Z.json`
- Baseline report: `reports/baseline.json`
- Defense analysis notes: `docs/DEFENSE_EVALUATION.md`
- Raw per-run probe logs: `reports/attack_results_*.jsonl`
