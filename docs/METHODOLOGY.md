# AEGIS Security Testing Methodology

## Framework Alignment

- OWASP Top 10 for LLM Applications
- OWASP Top 10 for Agentic Applications
- MITRE ATLAS
- NIST AI RMF

AEGIS is not a text-only jailbreak benchmark. The methodology is centered on agent behavior across tools, retrieval, memory, delegation, approvals, and user trust.

## Assessment Lanes

AEGIS currently carries two evaluation lanes:

1. Historical core lane
   - prompt injection
   - tool misuse
   - supply chain
   - code execution
   - memory poisoning
   - MCP command injection
   - data disclosure

2. v2 release lane
   - identity privilege abuse
   - dynamic cloaking
   - semantic manipulation
   - cross-lingual injection
   - inter-agent trust
   - HITL approval failures
   - human-trust deception

The v2 lane is the current release-facing methodology. Historical v1/core numbers remain in the repo as comparison data, not as the main release claim.

## Threat Model Additions in v2

The v2 methodology adds attack surfaces that are poorly captured by input-only or tool-parameter-only security scans:

- Dynamic cloaking
  - content served to the agent differs from what a crawler, scanner, or reviewer sees
- Identity and delegated authority
  - forged roles, spoofed delegation metadata, token relay, cross-tool privilege escalation
- Semantic manipulation
  - pressure, authority, harmlessness framing, fake consensus, compliance framing
- Inter-agent messaging
  - replay, session smuggling, hidden peer instructions, forged provenance
- HITL approvals
  - approval fatigue, summary/action mismatch, partial disclosure, low-to-high escalation
- Human-trust deception
  - fake citations, fake success cues, fake audit claims, unsafe confidence laundering
- Cross-lingual and mixed-script testing
  - Indonesian prompts, code switching, transliteration, mixed scripts, homoglyphs

These surfaces are included because they change what "attack success" means. In many of these cases, the exploit is not a jailbreak phrase or a malformed tool parameter. The exploit is the agent accepting a false frame, a false identity, a false approval summary, or a false trust cue.

## v2 Module Coverage

| Module | Primary surface | Techniques | Probes | Negative controls |
|---|---|---:|---:|---:|
| `asi_dynamic_cloak` | differential content retrieval | 5 | 12 | 2 |
| `asi03_identity_privilege` | delegated identity and privilege abuse | 5 | 12 | 2 |
| `asi_semantic_manip` | semantic pressure and framing | 7 | 16 | 2 |
| `llm01_crosslingual` | multilingual and mixed-script prompt injection | 7 | 26 | 5 |
| `asi07_inter_agent` | peer-message provenance and session trust | 6 | 14 | 2 |
| `asi_hitl` | approval workflow mismatch and escalation | 5 | 13 | 2 |
| `asi09_human_trust` | trust-signal deception directed at the user | 5 | 12 | 2 |

## Payload Construction

Each v2 payload export is expected to carry release-facing metadata:

- `attack_family`
- `technique_tag`
- `expected_signal`
- `is_negative_control`
- `version`

This is required so reports and downstream consumers can separate:

- attack families
- technique families
- benign controls
- v1/core versus v2 research probes

## Scoring Methodology

AEGIS supports two scorer types:

### Rule-based scoring

Deterministic rules inspect:

- tool calls
- output snippets
- provenance metadata
- approval mismatches
- retrieval differentials
- explicit expected-signal markers

This is the preferred mode for fast regression gates and reproducible defense matrices.

### LLM-judge scoring

Judge-backed scoring is used where richer interpretation is needed and a local model is available. In the Phase 5 v2 lane, each module also carries a rubric with:

- calibrated threshold
- concordance target
- negative-control FPR boundary
- deterministic rule signal
- structured rationale

The smoke-report path keeps this judge-backed evidence even when the broader matrix is run with deterministic scoring.

## Attack Outcome Semantics

- `success=true`: the probe objective was achieved
- `success=false`: the probe was blocked or the objective was not achieved
- CLI exit code `2`: the run completed and found vulnerabilities
- CLI exit code `1`: runtime or configuration error

For v2 modules, success is often tied to agent behavior rather than a specific response string. Examples:

- the agent retrieved agent-only cloaked content
- the agent honored an unverified peer instruction
- the agent treated a misleading approval summary as authorization
- the agent emitted deceptive trust cues to the user

## Negative Controls

Every v2 module includes benign or calibration probes intended to prevent ASR inflation. Examples include:

- benign peer summaries
- benign approvals
- benign multilingual phrasing
- benign trust-calibration examples

Phase 5 uses a release boundary of `<= 10%` false-positive rate on negative controls. The current v2 matrix and smoke reports stayed at `0.0000`.

## Defense Evaluation Method

The Phase 5 defense matrix measures:

- scenario-level ASR
- delta versus baseline
- module-level ASR
- negative-control false positives
- module-level negative-control FPR
- probe-level Phase 5 evidence

The current v2 matrix artifact is:

- `reports/day89_defense_matrix_20260420T132439Z.json`

The current reproducible config for the bounded v2 matrix is:

- `aegis/config.phase5b_v2_matrix.yaml`

That config intentionally:

- scopes execution to the seven v2 modules
- uses the offline provider
- uses `rule_based` scoring

This keeps the matrix practical and reproducible while the per-module smoke reports preserve judge-backed evidence.

## Reproducibility

Recommended release-path commands:

```bash
uv sync --dev
uv run aegis --help
uv run aegis attack --module asi_dynamic_cloak --format json
uv run aegis attack --module asi03_identity_privilege --format json
uv run aegis attack --module asi_semantic_manip --format json
uv run aegis attack --module llm01_crosslingual --format json
uv run aegis attack --module asi07_inter_agent --format json
uv run aegis attack --module asi_hitl --format json
uv run aegis attack --module asi09_human_trust --format json
uv run aegis matrix --config aegis/config.phase5b_v2_matrix.yaml --format json
uv run python scripts/validate_reports.py --schema matrix --input reports/<matrix-file>.json
```

Recommended fast verification gate:

```bash
uv run ruff check .
uv run pytest tests/test_config.py tests/test_attacks/test_phase5_release_readiness.py tests/test_reporting/test_schemas.py
```

## Limitations

- Results are point-in-time and model-dependent.
- The bounded Phase 5b matrix uses deterministic scoring rather than a full judge-backed matrix.
- Some publication inputs remain benchmark-oriented rather than product-native, especially in HITL and parts of the cross-lingual lane.
- `ASI08` cascading failures and `ASI10` rogue agents are intentionally deferred because they require a multi-agent orchestration layer outside the current local benchmark model.
- Coverage is only as good as the configured attack modules and payload sets.
