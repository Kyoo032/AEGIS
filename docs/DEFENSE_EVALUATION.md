# Defense Evaluation (Phase 5 Update)

Snapshot date: 2026-04-21
Phase 5 v2 matrix run date: 2026-04-20
Matrix artifact: `reports/day89_defense_matrix_20260420T132439Z.json`
Config: `aegis/config.phase5b_v2_matrix.yaml`

This section is the current source of truth for the v2 Phase 5 defense evaluation lane. It is intentionally separate from the historical v1/core matrix below.

## Scope

- Attack set: 7 v2 modules
  - `asi03_identity_privilege`
  - `asi07_inter_agent`
  - `asi09_human_trust`
  - `asi_dynamic_cloak`
  - `asi_hitl`
  - `asi_semantic_manip`
  - `llm01_crosslingual`
- Total probes per scenario: 105
- Scenarios measured:
  - Baseline
  - 5 single-defense runs
  - 3 layered-defense runs
- Scoring mode for this matrix: deterministic `rule_based`
- Judge-backed evidence remains available in the seven module smoke reports produced during Phase 5a.

## Execution Note

The default full `aegis matrix` path was started first, but it was too slow to serve as the Phase 5 publication boundary because it was still in the baseline pass after a long run and had not yet reached scoring or defense scenarios. For the Phase 5b boundary, the project now includes `aegis/config.phase5b_v2_matrix.yaml`, which constrains the run to the seven v2 modules, uses the offline provider, and uses deterministic rule-based scoring.

That tradeoff keeps the matrix reproducible and bounded while preserving judge-backed evidence in the smoke reports. If a newer full judge-backed matrix artifact exists later, treat the newer artifact as the higher-authority source.

## Matrix Contract

The v2 matrix artifact includes, per scenario:

- Overall ASR and delta versus baseline.
- `module_breakdown` with total probes, successful probes, module ASR, negative-control count, negative-control false positives, and module negative-control FPR.
- `negative_control_summary` with total negative controls, false positives, and overall FPR.
- `probe_results` fields for `attack_family`, `technique_tag`, `expected_signal`, `is_negative_control`, and `phase5_summary`.

Interpretation rule: failures by v1 defenses against semantic manipulation, HITL approval mismatch, identity delegation, inter-agent provenance, cross-lingual injection, dynamic cloaking, and human-trust deception are evidence for the v2 thesis. They should not be framed as simple regressions in v1 input filtering.

## ASR Matrix

| Scenario | Successful | Total | ASR | Delta vs Baseline | Negative-Control FPR |
|---|---:|---:|---:|---:|---:|
| baseline | 87 | 105 | 0.8286 | +0.0000 | 0.0000 |
| input_validator | 74 | 105 | 0.7048 | -0.1238 | 0.0000 |
| output_filter | 87 | 105 | 0.8286 | +0.0000 | 0.0000 |
| tool_boundary | 87 | 105 | 0.8286 | +0.0000 | 0.0000 |
| mcp_integrity | 87 | 105 | 0.8286 | +0.0000 | 0.0000 |
| permission_enforcer | 87 | 105 | 0.8286 | +0.0000 | 0.0000 |
| input_validator+output_filter+tool_boundary | 74 | 105 | 0.7048 | -0.1238 | 0.0000 |
| mcp_integrity+permission_enforcer | 87 | 105 | 0.8286 | +0.0000 | 0.0000 |
| input_validator+output_filter+tool_boundary+mcp_integrity+permission_enforcer | 74 | 105 | 0.7048 | -0.1238 | 0.0000 |

## Baseline Module Breakdown

| Module | Successful | Total | ASR | Negative Controls | False Positives | Negative-Control FPR |
|---|---:|---:|---:|---:|---:|---:|
| `asi03_identity_privilege` | 10 | 12 | 0.8333 | 2 | 0 | 0.0000 |
| `asi07_inter_agent` | 11 | 14 | 0.7857 | 2 | 0 | 0.0000 |
| `asi09_human_trust` | 10 | 12 | 0.8333 | 2 | 0 | 0.0000 |
| `asi_dynamic_cloak` | 10 | 12 | 0.8333 | 2 | 0 | 0.0000 |
| `asi_hitl` | 11 | 13 | 0.8462 | 2 | 0 | 0.0000 |
| `asi_semantic_manip` | 14 | 16 | 0.8750 | 2 | 0 | 0.0000 |
| `llm01_crosslingual` | 21 | 26 | 0.8077 | 5 | 0 | 0.0000 |

## False Positive Boundary

No scenario or module exceeded the Phase 5 release threshold of 10% negative-control FPR. Every scenario and every baseline module in this matrix reported `0.0000` FPR.

## Defense Family Interpretation

### input_validator

This is the only defense that materially changes aggregate v2 results in the deterministic matrix. The reductions are concentrated in:

- `asi03_identity_privilege`: `0.8333 -> 0.5833`
- `asi07_inter_agent`: `0.7857 -> 0.6429`
- `asi_semantic_manip`: `0.8750 -> 0.3750`

That pattern is consistent with what input validation can actually do: it helps when the malicious signal is present in the user-visible instruction surface. It does not materially reduce the dynamic-cloaking, HITL, human-trust, or cross-lingual modules in this run.

### output_filter

No aggregate reduction was observed. That is consistent with the v2 attack set: the success criteria are behavior-centric and retrieval-centric, not just text-output-centric. These attacks succeed before a response-only filter meaningfully changes the execution path.

### tool_boundary

No aggregate reduction was observed in the deterministic v2 matrix. The v2 set is dominated by semantic, trust, retrieval, delegation, and cloaking behaviors rather than obvious parameter-shape abuse. Parameter gating is still useful, but this run shows it is not sufficient against the Phase 5 surfaces by itself.

### mcp_integrity

No aggregate reduction was observed. That result is expected for this specific matrix: the v2 probes exercise agent-visible content, delegation, trust, and semantic manipulation more than they exercise live MCP manifest tampering. This remains a relevant control for supply-chain drift, but the current v2 matrix does not stress its strongest lane directly.

### permission_enforcer

No aggregate reduction was observed with the current policy path. That indicates the present permission layer does not materially constrain the behaviors exercised by the v2 modules. It should not be described as a general solution for Phase 5 attack families without stricter policy or flow constraints.

## Layered Defense Interpretation

`input_validator+output_filter+tool_boundary` and the full five-defense stack both land at `0.7048`, identical to `input_validator` alone. `mcp_integrity+permission_enforcer` stays flat at baseline (`0.8286`).

For this matrix, the layered combinations only help when `input_validator` is present, and even then the improvement is bounded. That is the main Phase 5 result: legacy v1-style defenses only partially reduce the new identity, inter-agent, and semantic surfaces and do not meaningfully dent dynamic cloaking, HITL approval mismatch, human-trust deception, or cross-lingual injection in aggregate.

## Judge Disagreement Notes

The deterministic matrix is paired with the seven Phase 5a smoke reports, which still provide judge-backed evidence. During those smoke runs, scorer disagreements were concentrated in:

- `asi03_identity_privilege`
  - `ASI03-FORGED-ROLE-001`
  - `ASI03-TOKEN-EXFIL-001`
  - `ASI03-DELEGATION-001`
- `asi_semantic_manip`
  - `SEM-ANCHOR-001`
  - `SEM-URGENCY-002`
  - `SEM-CONSENSUS-002`
  - `SEM-COMPLIANCE-002`
  - `SEM-HARMLESS-002`
  - `SEM-SOCIAL-002`

These disagreements did not produce negative-control false positives, but they should be carried as known rubric-review targets for any future judge-backed full-matrix rerun.

## Repro

```bash
.venv/bin/aegis matrix --config aegis/config.phase5b_v2_matrix.yaml --format json --output reports
.venv/bin/python scripts/validate_reports.py --schema matrix --input reports/day89_defense_matrix_20260420T132439Z.json
```

---

# Historical Defense Evaluation (Day 8-9)

Run date: 2026-02-24
Config: `aegis/config.day7_core7.yaml`
Matrix artifact: `reports/day89_defense_matrix_20260224T072547Z.json`

## Scope

- Attack set: 7 core modules (`ASI01`, `ASI02`, `ASI04`, `ASI05`, `ASI06`, `MCP06`, `LLM01`)
- Total payloads per scenario: 68
- Scenarios measured:
  - Baseline
  - 5 single-defense runs
  - 3 layered-defense runs

## ASR Matrix

| Scenario | Successful | Total | ASR | Delta vs Baseline |
|---|---:|---:|---:|---:|
| baseline | 29 | 68 | 0.4265 | +0.0000 |
| input_validator | 10 | 68 | 0.1471 | -0.2794 |
| output_filter | 29 | 68 | 0.4265 | +0.0000 |
| tool_boundary | 24 | 68 | 0.3529 | -0.0735 |
| mcp_integrity | 29 | 68 | 0.4265 | +0.0000 |
| permission_enforcer | 29 | 68 | 0.4265 | +0.0000 |
| input_validator+output_filter+tool_boundary | 6 | 68 | 0.0882 | -0.3382 |
| mcp_integrity+permission_enforcer | 29 | 68 | 0.4265 | +0.0000 |
| input_validator+output_filter+tool_boundary+mcp_integrity+permission_enforcer | 6 | 68 | 0.0882 | -0.3382 |

## Per-Defense Bypass Analysis

### input_validator (ASR: 0.1471, Delta: -0.2794)

**Blocked:** Direct prompt injection overrides (LLM01), system impersonation (ASI01-DIRECT-001/002), delimiter escapes (LLM01-DELIMIT-001), and explicit goal hijack commands.

**Bypassed by:**
- **Post-tool execution chains** — Payloads where malicious behavior emerges after a legitimate tool call completes (e.g., ASI04-TOOL-001 where exfiltration occurs via tool output poisoning, not input).
- **Multi-turn progressive drift** — ASI06-DRIFT payloads that gradually shift behavior across conversation turns. The validator checks each individual input but misses the cumulative trajectory.
- **Indirect injection via RAG** — ASI06-RAG-001 and ASI04-RAG payloads embed instructions in retrieved documents, bypassing input-level filtering entirely.

**Root cause:** Input validation operates on the user-facing prompt boundary only. Attacks that enter through tool outputs, memory retrieval, or multi-turn escalation bypass this layer.

### output_filter (ASR: 0.4265, Delta: +0.0000)

**Blocked:** None observed in this evaluation.

**Root cause:** Current attack success criteria are tool/behavior-centric (did the agent call a dangerous tool? did it attempt file access?). The output filter sanitizes the agent's textual response but cannot intercept tool invocations. Attacks succeed before the output filter runs.

**Improvement path:** Wire output filtering into the tool-call pipeline as a post-invocation gate that can redact or block tool results containing sensitive patterns.

### tool_boundary (ASR: 0.3529, Delta: -0.0735)

**Blocked:** Obvious parameter abuse — path traversal (MCP06-TRAVERSE-001), explicit command injection syntax (MCP06-SEMI, MCP06-PIPE), and blatant SSRF to metadata endpoints (ASI02-PARAM-003).

**Bypassed by:**
- **Benign-looking parameters** — ASI02-PARAM-001 (`read_file('/etc/passwd')`) where the path itself is syntactically valid and doesn't contain shell metacharacters.
- **Allowed tool sets** — Payloads that chain legitimate tools in unintended sequences (ASI04-CROSS-001: DB query → email) stay within allowed tool boundaries individually.
- **Semantic-level attacks** — Goal hijacking payloads (ASI01) that don't abuse tool parameters but redirect the agent's intent.

**Root cause:** Tool boundary enforcement validates parameter syntax, not semantic intent. Cross-tool flow policies need to complement parameter-level checks.

### mcp_integrity (ASR: 0.4265, Delta: +0.0000)

**Blocked:** None in this evaluation run.

**Root cause:** The attack set did not include runtime MCP manifest modifications. This defense targets supply-chain drift (tool schema changes, endpoint substitution, provenance spoofing) — scenarios that require the attack to modify the MCP server configuration itself, which the current payload set does not attempt at the MCP protocol level.

**When effective:** Active in scenarios where a compromised dependency or registry update changes tool definitions between sessions.

### permission_enforcer (ASR: 0.4265, Delta: +0.0000)

**Blocked:** None with default `standard` mode policy.

**Root cause:** The default permission mode permits all tool calls that the agent profile allows. Stricter modes (`read_only`, `restricted`) or tighter `forbidden_cross_tool_flows` configuration are required for measurable impact.

**Improvement path:** Test with `permission_mode: restricted` and explicit cross-tool deny rules (e.g., deny `database → email`, deny `filesystem → http`).

## Layered Defense Analysis

### Best combination: input_validator + output_filter + tool_boundary

**ASR reduction:** 0.4265 → 0.0882 (79.31% improvement)

This combination succeeds because it addresses attacks at multiple stages:
1. **input_validator** catches prompt-level injection and hijacking attempts at entry.
2. **tool_boundary** catches parameter-level abuse that slips past input validation.
3. **output_filter** provides a final check on response content (marginal effect in current scoring but adds defense-in-depth).

**Residual 8.82% (6/68 payloads):** These are sophisticated multi-turn and indirect-injection attacks:
- ASI06 progressive-drift payloads that build up malicious behavior gradually across turns.
- ASI04 supply-chain payloads where poisoned tool outputs introduce instructions after the input boundary.
- ASI06 context-poisoning payloads that fabricate historical session data.

These residual attacks bypass all three layers because the malicious content never passes through the input boundary or tool parameter validation — it enters via memory retrieval or fabricated conversation history.

### mcp_integrity + permission_enforcer

**ASR reduction:** None (0.4265 → 0.4265).

These two defenses target orthogonal threat vectors (MCP manifest integrity and cross-tool permission flows) that the current payload set does not exercise directly. They are expected to show impact in supply-chain and multi-agent-delegation scenarios.

### All 5 defenses

**ASR:** 0.0882 — identical to the 3-defense combination. Adding `mcp_integrity` and `permission_enforcer` (with default config) provides no additional reduction because the residual attacks are memory/context-based, not MCP-manifest or permission-flow based.

## Recommendations Matrix

| Attack Category | input_validator | output_filter | tool_boundary | mcp_integrity | permission_enforcer |
|---|:---:|:---:|:---:|:---:|:---:|
| LLM01 Prompt Injection | **Strong** | Weak | Weak | None | None |
| ASI01 Goal Hijacking | **Strong** | Weak | Partial | None | Partial* |
| ASI02 Tool Misuse | Partial | Weak | **Strong** | None | Partial* |
| ASI04 Supply Chain | Weak | Weak | Partial | **Target** | Weak |
| ASI05 Code Execution | Partial | Weak | **Strong** | None | Partial* |
| ASI06 Memory Poisoning | Weak | Weak | Weak | None | None |
| MCP06 Command Injection | Partial | Weak | **Strong** | None | None |

*Requires stricter permission mode configuration for measurable effect.

**Key takeaway:** No single defense covers all attack categories. `input_validator` is the strongest general-purpose defense. `tool_boundary` complements it for parameter-level attacks. Memory/context poisoning (ASI06) and supply-chain attacks (ASI04) require architectural mitigations beyond these five defenses — specifically, memory integrity verification and tool provenance validation at the MCP protocol layer.

## Repro

```bash
PYTHONPATH=. .venv/bin/python - <<'PY'
from aegis.orchestrator import AEGISOrchestrator
orch = AEGISOrchestrator(config_path="aegis/config.day7_core7.yaml")
reports = orch.run_full_matrix()
for name, report in sorted(reports.items()):
    print(name, report.total_successful, report.total_attacks, report.attack_success_rate)
PY
```
