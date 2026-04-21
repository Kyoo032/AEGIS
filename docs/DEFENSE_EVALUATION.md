# Defense Evaluation

## Current status

There are now two relevant evidence lanes in the repo:

1. the Phase 5 defense-matrix lane, which measures defense deltas across the v2-focused scenarios
2. the April 21, 2026 local live baseline lane, which revalidated the full attack corpus against a single local Qwen model

They are not the same run and should not be conflated.

## Latest live local baseline

- Date: April 21, 2026
- Config: [config.local_single_qwen.yaml](/home/kyo/AEGIS/aegis/config.local_single_qwen.yaml)
- Model: `qwen3.5:0.8b`
- Artifact: [baseline.json](/home/kyo/AEGIS/reports/baseline.json)
- Scope: baseline only, no fresh defense-matrix rerun in this pass

Key implication: the expanded corpus remains highly exploitable in a realistic one-model local setup. The fresh baseline does not invalidate the earlier matrix, but it does confirm that the newer attack families are not paper-only additions.

## Phase 5 matrix source of truth

The current Phase 5 matrix artifact is:

- [day89_defense_matrix_20260421T085027Z.json](/home/kyo/AEGIS/reports/day89_defense_matrix_20260421T085027Z.json)

That matrix was the scoped Phase 5b v2 run and remains the best structured defense-comparison artifact currently in the repo.

### Scenario summary

| Scenario | ASR | FPR |
|---|---:|---:|
| baseline | `0.8286` | `0.0000` |
| `input_validator` | `0.7048` | `0.0000` |
| `output_filter` | `0.8286` | `0.0000` |
| `tool_boundary` | `0.8286` | `0.0000` |
| `mcp_integrity` | `0.8286` | `0.0000` |
| `permission_enforcer` | `0.8286` | `0.0000` |
| `input_validator+output_filter+tool_boundary` | `0.7048` | `0.0000` |
| `mcp_integrity+permission_enforcer` | `0.8286` | `0.0000` |
| all five defenses | `0.7048` | `0.0000` |

## Interpretation

### 1. Input validation still matters, but it is not enough

`input_validator` is the only single defense that materially moved the v2 matrix. Even then, it reduced ASR only from `0.8286` to `0.7048`.

### 2. Several defenses are currently neutral against the expanded corpus

`output_filter`, `tool_boundary`, `mcp_integrity`, and `permission_enforcer` showed no aggregate ASR reduction in the Phase 5 matrix as currently configured.

That does not mean they are useless in principle. It means the present payload set is hitting surfaces they do not currently control well enough:

- semantic reframing
- identity delegation
- human approval abuse
- inter-agent provenance failures
- cloaked instructions

### 3. The newer surfaces are the real release blocker

The fresh local baseline and the Phase 5 matrix point in the same direction: the hardest problems are not classical single-turn prompt injection anymore. They are trust-boundary failures around:

- approval summaries
- forged authority
- multilingual and mixed-script instructions
- semantic pressure and social framing
- poisoned or cloaked context

## Current limits

The April 21 local run also exposed a local evaluation constraint:

- local Qwen runs are stable enough for payload execution
- LLM-judge structured verdicts are still intermittently unparseable on the same single-model path

That means rule-based evidence remains the more reliable baseline for one-model local runs. A future defense rerun should either:

1. use a more stable dedicated judge model, or
2. keep the local low-VRAM path rule-based by default and treat judge results as optional

## Repro

Baseline live run:

```bash
uv run aegis scan --config aegis/config.local_single_qwen.yaml --format json --output reports
```

Phase 5 matrix artifact validation:

```bash
uv run python scripts/validate_reports.py --schema matrix --input reports/day89_defense_matrix_20260421T085027Z.json
```
