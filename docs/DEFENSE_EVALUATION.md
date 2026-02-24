# Defense Evaluation (Day 8-9)

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

## Bypass Notes

- `input_validator`:
  - Reduces direct prompt-injection style payload success substantially.
  - Residual bypasses are mostly non-input-centric chains where malicious behavior appears after tool execution.
- `output_filter`:
  - No observed ASR reduction in this matrix.
  - Current success criteria are tool/behavior-centric; output-only filtering does not currently move the scorer result.
- `tool_boundary`:
  - Partial reduction only; current policy is effective for obvious parameter abuse but permissive for broader tool strategies.
  - Evasion pattern: payloads that stay inside allowed tool sets and benign-looking parameters.
- `mcp_integrity`:
  - No baseline delta in this run because attacks did not modify runtime MCP manifests.
  - This defense primarily targets supply-chain/tool-poisoning drift, not pure prompt-level exploits.
- `permission_enforcer`:
  - No baseline delta with default `standard` mode policy.
  - Stronger effect requires stricter mode (`read_only` / `restricted`) or tighter `forbidden_cross_tool_flows`.

## Layered Defense Findings

- `input_validator+output_filter+tool_boundary` reduced ASR from `0.4265` to `0.0882`.
- Adding `mcp_integrity+permission_enforcer` to that stack did not further reduce ASR in this run.
- `mcp_integrity+permission_enforcer` alone did not reduce ASR in this configuration.

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
