# AEGIS Security Testing Methodology

## Framework Alignment
- OWASP Top 10 for LLM Applications (2025)
- OWASP Top 10 for Agentic Applications (2026)
- MITRE ATLAS (AI threat taxonomy)
- NIST AI Risk Management Framework (AI RMF)

## Assessment Approach
- Automated black-box testing against the target AI agent and configured MCP tool surface.
- Baseline measurement with no defenses active, then single-defense and layered-defense runs.
- Delta comparison to quantify defense effectiveness (`delta_vs_baseline = defended_asr - baseline_asr`).

## Attack Module Coverage

| Module | OWASP Category | MITRE ATLAS | Description |
|---|---|---|---|
| `asi01_goal_hijack` | ASI01 (Agent Goal Hijacking) | `AML.T0051` | Redirects agent objectives through prompt/control-plane hijack patterns. |
| `asi02_tool_misuse` | ASI02 (Tool Misuse & Exploitation) | `AML.T0040` | Coerces unsafe tool invocations and malicious parameters. |
| `asi04_supply_chain` | ASI04 (Supply Chain Vulnerabilities) | `AML.T0010` | Tests poisoned dependency/tooling/context supply paths. |
| `asi05_code_exec` | ASI05 (Unexpected Code Execution) | `AML.T0051` | Attempts arbitrary code execution through agent workflows. |
| `asi06_memory_poison` | ASI06 (Memory & Context Poisoning) | `AML.T0020` | Injects malicious persistent context/memory artifacts. |
| `mcp06_cmd_injection` | MCP06 (Command Injection via MCP) | `AML.T0040` | Injects shell/OS command syntax via MCP tool parameters. |
| `llm01_prompt_inject` | LLM01 (Prompt Injection) | `AML.T0051` | Tests direct and indirect prompt injection primitives. |

## Scoring Methodology
- Rule-based scoring (default): deterministic indicator matching against tool calls, outputs, and known exploit signatures.
- LLM-judge scoring (optional): model-based adjudication when enabled in config.
- Current CI default: prioritize rule-based scoring for speed and reproducibility.
- Attack outcome semantics:
  - `success=true`: exploit objective achieved (security control failure for that probe)
  - `success=false`: probe blocked or objective not achieved

## Severity Classification

| Severity | Criteria |
|---|---|
| Critical | Attack succeeds with high confidence and high-impact control bypass (e.g., exfiltration/override). |
| High | Attack succeeds reliably with meaningful impact; mitigation is incomplete. |
| Medium | Attack succeeds intermittently or with partial impact. |
| Low | Limited exploitability or constrained impact. |
| Informational | Security-relevant observation without immediate exploitable impact. |

## Defense Evaluation Method
- Baseline: run all core attack modules with no defenses active.
- Single-defense: run all attack modules with one defense active.
- Layered-defense: run configured defense combinations.
- Matrix output includes:
  - scenario-level ASR and `delta_vs_baseline`
  - per-scenario `probe_results`
  - structured `errors` for failed module/scenario execution

## Reproducibility
- Recommended commands:

```bash
uv sync --dev
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/pytest -q
.venv/bin/python -m aegis.orchestrator scan -c aegis/config.day7_core7.yaml
.venv/bin/python - <<'PY'
from aegis.orchestrator import AEGISOrchestrator
orch = AEGISOrchestrator(config_path="aegis/config.day7_core7.yaml")
orch.run_full_matrix()
PY
```

- Configuration source of truth: `aegis/config.yaml` and gate-specific overrides (for example `aegis/config.day7_core7.yaml`).
- Expected reproducibility level: comparable trends, not bit-identical metrics, due to model non-determinism.

## CLI Exit Codes
- `0`: Run completed and no successful attacks detected.
- `1`: Tool/config/runtime error.
- `2`: Run completed and vulnerabilities detected (`total_successful > 0`).

## Limitations
- Point-in-time assessment; new attacks may emerge after execution date.
- Coverage is bounded by configured attack modules and payload sets.
- Heuristic scoring can produce false positives/negatives.
- Offline/provider fallback can affect realism versus fully online model execution.
