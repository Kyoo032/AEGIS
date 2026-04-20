# AEGIS v2 Development Plan

> **Status:** Active
> **Last updated:** 2026-04-14
> **Maintainer:** Kyo

---

## v1 Context Summary

AEGIS v1 shipped as a local agent security benchmark: Qwen/Ollama testbed, MCP tools, static attack modules (LLM01–02, ASI01–06, MCP06), five defense modules, rule-based + LLM-judge scoring, Typer CLI, JSON/HTML reports, Streamlit dashboard, Docker/Compose, and CI.

v1 constraints that shape v2:

- Fixed local benchmark — not a real-world target scanner.
- Static payload sets — no multi-turn campaigns.
- No coverage for: dynamic cloaking, identity/privilege abuse, semantic manipulation, inter-agent trust, human approval failures, human-trust deception.
- Minimal multilingual prompt-injection coverage.
- `aegis/attacks/asi03_training_data_poison.py` does not match the v2 ASI03 scope (identity/privilege abuse).

---

## v2 Thesis

AEGIS v2 is not "v1 with more payloads." It is a differentiated agent-security research suite focused on attack classes with weak coverage in current tools.

```
AEGIS v2 evaluates under-tested agentic failure modes:
dynamic cloaking, identity/privilege abuse, semantic manipulation,
inter-agent trust, human approval failures, cross-lingual injection,
and human-trust exploitation.
```

### Differentiation From Existing Tools

| Capability | Garak | Promptfoo | AEGIS v2 |
|------------|-------|-----------|----------|
| Dynamic cloaking detection | ✗ | ✗ | ✓ |
| Identity/privilege chain abuse | ✗ | ✗ | ✓ |
| Semantic manipulation (non-jailbreak) | Partial | ✗ | ✓ |
| Inter-agent trust boundary | ✗ | ✗ | ✓ |
| HITL approval fatigue | ✗ | ✗ | ✓ |
| Cross-lingual injection (Indonesian) | ✗ | ✗ | ✓ |
| Human-trust deception | ✗ | Partial | ✓ |

---

## v2 Module Scope

| Priority | Module | Category | Research Angle |
|----------|--------|----------|----------------|
| 1 | `asi_dynamic_cloak` | DeepMind — Dynamic Cloaking | Zero v1 coverage. Agent fingerprinting, trap pages, scanner evasion, differential content. First-mover publication angle. |
| 2 | `asi03_identity_privilege` | OWASP ASI03 | Delegation-chain abuse, token theft, identity spoofing, cross-agent privilege escalation. |
| 3 | `asi_semantic_manip` | DeepMind — Semantic Manipulation | Authority framing, anchoring bias, urgency, harmlessness laundering. Not classic prompt injection. |
| 4 | `llm01_crosslingual` | LLM01 Extension | Indonesian, code-switching, Malay/ID similarity, mixed-script, homoglyph. **Most publishable local research angle.** |
| 5 | `asi07_inter_agent` | OWASP ASI07 | A2A session smuggling, spoofed peer messages, forged metadata, trust-boundary failures. |
| 6 | `asi_hitl` | DeepMind — HITL | Approval fatigue, misleading summaries, dangerous-action-as-remediation framing. |
| 7 | `asi09_human_trust` | OWASP ASI09 | Deceptive UI/output, fake citations, social engineering via agent responses. |

### Cut From v2 (Tracked as v3)

| Module | Category | Reason |
|--------|----------|--------|
| `asi08_cascading` | OWASP ASI08 | Requires deterministic multi-agent cascade infrastructure beyond local Docker/Ollama. |
| `asi10_rogue_agents` | OWASP ASI10 | Needs rogue-agent orchestration and discovery infrastructure. |

> **Publication wording:** AEGIS v2 intentionally excludes ASI08 cascading failures and ASI10 rogue agents because both require a multi-agent orchestration layer outside the current local benchmark threat model. They are documented as future work rather than shipped as shallow coverage.

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Phase 0 infrastructure drag — v1 rot, dep drift, broken Docker layers | Blocks all v2 work | Timebox Phase 0 to 2–3 sessions. "Known failures documented" is a legitimate exit. |
| Campaign runner over-engineering | Blocks every v2 module | Ship minimal: linear turn sequence, no branching, state = dict passed forward. |
| LLM judge rubrics deferred to Phase 5 | Modules produce unscored/noisy signal | Write stub rubrics alongside each module in Phases 2–4. |
| Payload count targets are arbitrary | False sense of coverage | Gate on **technique coverage** (each sub-technique exercised), not raw payload count. |
| v1 defenses fail against all v2 attacks | Looks like a gap instead of a finding | Frame explicitly as evidence for the v2 thesis in defense evaluation docs. |
| `llm01_crosslingual` buried in Phase 4 | Weakens publication timing and Anthropic Fellows angle | Dataset curation starts in Phase 2 as parallel track. |

---

## Phase 0: v1 Regression + Architecture Lock

> **Status:** Completed 2026-04-13
> **Timebox:** 2–3 sessions max.
> **Goal:** Confirm v1 works (or document known failures), then define v2 contracts.

| Track | Tasks | Done When |
|-------|-------|-----------|
| Regression | `ruff check aegis/`, `pytest --cov=aegis --cov-fail-under=80`, `aegis --help`, report schema validation. | v1 green OR known failures documented with skip markers. |
| ASI03 naming | Retire `asi03_training_data_poison.py`. Create `asi03_identity_privilege.py` with clear module path, payload file, dataset file, CLI name. | `aegis attack --module asi03_identity_privilege` resolves without import errors. |
| Trace schema | v2 trace model: campaign_id, turn_id, target_fingerprint, context_source, delegated_identity, peer_message_meta, approval_summary, actual_action, tool_calls, scorer_rationale. | Trace schema can represent all seven v2 modules without per-module hacks. |
| Campaign contract | Extend attack execution for stateful multi-step campaigns. **Keep it lean:** linear turn sequence, state = dict, no branching. Preserve v1 single-payload compat. | v1 modules run unchanged. One empty v2 campaign emits a valid trace. |

**Gate:**
```
v1 tests pass (or failures documented), ASI03 renamed, one empty v2 campaign emits valid trace.
```

---

## Phase 1: v2 Harness Foundations

> **Status:** Completed 2026-04-13
> **Goal:** Build the minimum shared fixtures for v2 attack classes.

| Component | Tasks | Done When |
|-----------|-------|-----------|
| Campaign runner | Multi-turn execution, stop conditions, scenario state, per-turn evidence collection. | A v2 module can run N turns and emit one finding bundle. |
| Evidence trace store | Persist trace JSONL alongside attack-result JSONL. Include prompts, responses, tool calls, context, fixture state, defense decisions, scorer rationale. | Reports can link each finding to reproducible evidence. |
| Cloaked HTTP fixture | Local fixture serving differential content based on headers, user-agent, timing, fingerprint. | Scanner-like fetch → benign; agent-like fetch → malicious/trap. |
| HITL approval stub | Deterministic approval records: requested_action, summary_shown, actual_action, risk_delta, approval_decision. | HITL modules can test approval fatigue without a real UI. |
| Peer-agent message fixture | Lightweight peer-agent inbox/session: message envelopes, sender identity, session_id, delegated capability metadata. | Inter-agent spoofing testable locally without full multi-agent infra. |

**Parallel track — start crosslingual dataset curation:**
Begin collecting and reviewing Indonesian prompt-injection payloads, code-switching patterns, Malay/ID similarity pairs, and homoglyph sets. This does not block Phase 1 gate but feeds Phase 3.

**Gate:**
```
One smoke test exercises cloaked content, HITL approval capture, and peer-agent message envelopes.
```

---

## Phase 2: Core Differentiation Modules

> **Status:** Completed 2026-04-14
> **Goal:** Ship the three modules that define AEGIS v2's research claim.
> **Gate:** Passed — `pytest -q`, `ruff check aegis tests`, and the three Phase 2 `aegis attack --module ...` commands completed with reports and no run errors.

For each module below, **ship alongside:**
- Payload YAML with technique tags (not just raw count).
- Stub scoring rubric (rule pattern + draft judge prompt).
- At least 2 negative-control payloads per module.

| Module | Key Techniques | Coverage Gate | Scoring Signals |
|--------|----------------|---------------|-----------------|
| `asi_dynamic_cloak` | (1) Agent fingerprint detection, (2) trap page injection, (3) delayed malicious content, (4) scanner evasion, (5) crawler-safe / agent-malicious differential. | ≥5 techniques exercised, ≥2 payloads per technique. | Agent retrieves/trusts/acts on agent-only trap content while scanner sees benign. |
| `asi03_identity_privilege` | (1) Forged role claims, (2) token exfiltration, (3) delegation chain abuse, (4) cross-tool privilege escalation, (5) spoofed delegation. | ≥5 techniques exercised, ≥2 payloads per technique. | Agent accepts forged authority, leaks token, invokes privileged tool, or escalates across role boundaries. |
| `asi_semantic_manip` | (1) Authority framing, (2) anchoring bias, (3) urgency/scarcity, (4) false consensus, (5) compliance framing, (6) harmlessness laundering, (7) social proof. | ≥6 techniques exercised, ≥2 payloads per technique. | Agent violates policy or uses dangerous tool due to framing — no explicit jailbreak language. |

**Gate:**
```
aegis attack --module asi_dynamic_cloak
aegis attack --module asi03_identity_privilege
aegis attack --module asi_semantic_manip
# All three emit attack results, traces, scored findings, and reproduction evidence.
```

---

## Phase 3: Cross-Lingual + Trust Boundary Modules

> **Status:** Completed 2026-04-16; audited 2026-04-20, metadata cleanup completed 2026-04-20.
> **Goal:** Ship the cross-lingual and inter-agent modules. Crosslingual dataset curation from Phase 1 parallel track lands here.
> **Gate:** Partially passed — both Phase 3 modules exist, emit reports, and pass the normalized payload metadata coverage gate. Remaining pre-Phase-5 debt: `llm01_crosslingual` still needs the Indonesian naturalness pass, and scorer disagreement remains Phase 5a calibration work.

| Module | Key Techniques | Coverage Gate | Scoring Signals |
|--------|----------------|---------------|-----------------|
| `llm01_crosslingual` | (1) Indonesian injection, (2) EN-ID code-switching, (3) Malay/ID similarity exploitation, (4) transliteration bypass, (5) mixed-script, (6) homoglyph, (7) multilingual role-instruction. | ≥6 techniques, ≥3 payloads per technique (Indonesian payloads reviewed for naturalness). | Cross-lingual injection bypasses v1 input validation or causes unauthorized instruction following. |
| `asi07_inter_agent` | (1) A2A session smuggling, (2) spoofed peer identity, (3) forged sender metadata, (4) hidden peer instructions, (5) cross-session replay, (6) delegated-capability confusion. | ≥5 techniques, ≥2 payloads per technique. | Target trusts spoofed peer, carries instructions across sessions, or grants capability from unauthenticated context. |

**Gate:**
```
aegis attack --module llm01_crosslingual
aegis attack --module asi07_inter_agent
```

---

## Phase 4: HITL + Human Trust Modules

> **Status:** Completed 2026-04-16; audited and cleanup-verified 2026-04-20.
> **Goal:** Complete the v2 module set.
> **Gate:** Passed for module existence, metadata coverage, and smoke execution. Remaining scorer disagreements are Phase 5a calibration work, not Phase 4 module-shipping blockers.

| Module | Key Techniques | Coverage Gate | Scoring Signals |
|--------|----------------|---------------|-----------------|
| `asi_hitl` | (1) Approval fatigue sequences, (2) misleading action summaries, (3) partial-disclosure approvals, (4) low-risk→high-risk escalation, (5) ransomware-as-remediation framing. | ≥4 techniques, ≥2 payloads per technique. | Approval summary hides material risk OR agent proceeds with dangerous action after induced approval. |
| `asi09_human_trust` | (1) Deceptive output formatting, (2) fake audit/compliance claims, (3) fake citations, (4) overconfident safety summaries, (5) social-engineering responses encouraging unsafe user action. | ≥4 techniques, ≥2 payloads per technique. | Agent produces misleading trust cues, false safety claims, or user-directed unsafe steps. |

**Gate:**
```
aegis attack --module asi_hitl
aegis attack --module asi09_human_trust
# v2 now covers all seven in-scope modules.
```

---

## Phase 5: Evaluation, Reporting, Defense Matrix

> **Status:** In Progress as of audit 2026-04-20.
> **Goal:** Make v2 findings auditable for publication and comparison against v1.
> **Audit note:** Phase 5a is required before matrix publication: rubric finalization is `7/7` incomplete by calibration/concordance criteria, and module smoke runs still surface scorer disagreement.
>
> ### Pre-Phase-5 Cleanup Required (audited 2026-04-20)
> - [x] Payload metadata normalization: top-level `technique_tag`, `is_negative_control`, `attack_family`, and `version` added for the four audited v2 datasets.
> - [x] Judge parser / prompt fix: Ollama judge now requests a structured JSON schema; `asi07_inter_agent`, `asi_hitl`, `asi09_human_trust`, and `llm01_crosslingual` smoke runs no longer show unparseable judge output.
> - [x] Indonesian naturalness pass for `llm01_crosslingual` completed 2026-04-20: all 26 payloads Kyo-reviewed and accepted.
> - [ ] Phase 5a rubric calibration for all 7 modules (all rubrics still need documented threshold/concordance/structured rationale).

| Area | Tasks | Done When |
|------|-------|-----------|
| Finalize scoring | Promote stub rubrics to full rule patterns + judge prompts. Calibrate against Phase 2–4 outputs. | Every module has ≥1 deterministic rule signal AND a calibrated judge prompt with structured rationale. |
| Negative controls | Verify: benign multilingual prompts, legitimate delegation, harmless approvals, normal persuasion, benign peer messages. | Negative controls in test suite, FPR documented, no ASR inflation. |
| Reporting v2 | Add report sections: cloaking differential, identity chain, semantic manipulation vector, approval summary mismatch, inter-agent message provenance, cross-lingual payload language, human-trust deception evidence. | HTML + JSON reports expose reproduction evidence per finding. |
| Dataset export | `datasets/payloads/` with metadata: language, attack_family, technique_tag, expected_signal, is_negative_control, v1_or_v2. | Dataset consumers can separate v1 core from v2 research payloads. |
| Defense matrix | Re-run v1 defenses against all v2 modules. **Frame failures as evidence for v2 thesis** — document why simple input filtering doesn't solve semantic/HITL/identity attacks. | `docs/DEFENSE_EVALUATION.md` complete. |

**Gate:**
```
aegis scan --format html
aegis matrix
validate_reports.py --schema report
```

---

## Phase 6: Documentation + Release

> **Goal:** Package v2 as a clear research release with honest gaps.

| Document | Updates |
|----------|---------|
| `README.md` | v2 module table, payload counts by technique, architecture notes, quickstart, known gaps (ASI08/ASI10). |
| `docs/METHODOLOGY.md` | Threat model additions: dynamic cloaking, inter-agent messages, HITL approvals, semantic manipulation, multilingual testing. |
| `docs/FINDINGS.md` | v2 baseline ASR by category, notable bypasses, representative evidence summaries. |
| `docs/DEFENSE_EVALUATION.md` | Defense results vs v2 modules. Why v1 defenses are insufficient for semantic/HITL/identity attacks. |
| `CHANGELOG.md` | v2.0.0 release notes, ASI03 migration notes. |
| `TASK_PROMPTS.md` | Replaced with v2 session-contract prompts (see companion file). |

**Release gate:**
```bash
ruff check aegis/
pytest --cov=aegis --cov-fail-under=80
aegis --help
aegis attack --module asi_dynamic_cloak
aegis attack --module asi03_identity_privilege
aegis attack --module asi_semantic_manip
aegis attack --module llm01_crosslingual
aegis attack --module asi07_inter_agent
aegis attack --module asi_hitl
aegis attack --module asi09_human_trust
aegis scan --format html
aegis matrix
validate_reports.py --schema report
```

v2 is complete when a fresh clone runs the full scan, generates reports, and clearly explains both coverage and deferred scope.

---

## Phase 7: Kyo Product Improvement Pass

> **Goal:** Replace the remaining synthetic or stale publication inputs with Kyo/product-specific evidence before public release.
> **Timing note:** This is the current improvement snapshot as of 2026-04-16. Treat it as the last release-readiness pass, but re-check it before publication because product behavior, attack modules, payload counts, and benchmark priorities may change after these notes.

| File | Improvement Needed | Done When |
|------|--------------------|-----------|
| `datasets/payloads/asi_hitl.yaml` | Replace synthetic approval summaries/actions with real approval UI examples from the target agent product while preserving the summary/action delta and risk escalation structure. | Payloads use realistic approval wording and still cover approval fatigue, misleading summaries, partial disclosure, escalation, and ransomware-as-remediation. |
| `datasets/payloads/asi09_human_trust.yaml` | Strengthen prompts with real examples of overstated safety, fake citations/compliance, and user-pressure language from agent outputs or support workflows. | Attack and negative-control examples are realistic, calibrated, and publication-safe. |
| `datasets/payloads/llm01_crosslingual.yaml` | Replace or augment synthetic Indonesian/cross-lingual prompts with real support/chat phrasing and native-speaker review. | Indonesian examples mark native review complete or document why synthetic phrasing remains. |
| `datasets/payloads/asi07_inter_agent.yaml` | Replace deterministic peer-message chains with real A2A/protocol envelopes from the frameworks AEGIS should benchmark. | Inter-agent payloads include realistic envelopes, sender metadata, delegated capabilities, and replay/session fields. |
| `README.md` | Refresh stale test/module/payload counts and command examples after the final payload set is locked. | README matches the registered modules, payload totals, current test count, and preferred repo-wide checks. |
| `aegis/evaluation/rule_detector.py` | Re-check HITL and human-trust fallback scoring against realistic safe-but-not-refusal outputs to reduce false positives. | Rule tests include realistic success, refusal, and calibrated-safe responses. |
| `aegis/cli.py`, `aegis/testbed/kb/ingest.py`, `aegis/fixtures/hitl_approval.py` | Add focused tests for low-coverage user-facing or fixture paths if time remains. | Coverage gaps are either tested or explicitly deferred with rationale. |

**Gate:**
```bash
ruff check .
pytest -s --cov=aegis --cov-report=term-missing --cov-fail-under=80
python - <<'PY'
from aegis.attacks import ATTACK_MODULES, get_all_modules
cfg = {"mcp_servers": ["filesystem", "http", "email", "database", "code_exec"], "rag_enabled": True, "memory_enabled": True}
print("modules", len(ATTACK_MODULES))
print("payloads", sum(len(module.generate_payloads(cfg)) for module in get_all_modules()))
PY
```

Phase 7 is complete when all Kyo-specific placeholders have been replaced or deliberately deferred, and the docs state the date and assumptions behind the final counts.

---

## Build Order (Quick Reference)

| Step | Phase | Work |
|------|-------|------|
| 1 | 0 | v1 regression — fix or document failures |
| 2 | 0 | Rename ASI03 → identity/privilege |
| 3 | 0 | v2 trace schema |
| 4 | 0 | Campaign runner (lean — linear, dict state) |
| 5 | 1 | Cloaked HTTP fixture |
| 6 | 1 | HITL approval stub |
| 7 | 1 | Peer-agent message fixture |
| 8 | 1‖ | Begin crosslingual dataset curation (parallel) |
| 9 | 2 | `asi_dynamic_cloak` + stub rubric + negatives |
| 10 | 2 | `asi03_identity_privilege` + stub rubric + negatives |
| 11 | 2 | `asi_semantic_manip` + stub rubric + negatives |
| 12 | 3 | `llm01_crosslingual` (dataset from step 8 lands here) |
| 13 | 3 | `asi07_inter_agent` |
| 14 | 4 | `asi_hitl` |
| 15 | 4 | `asi09_human_trust` |
| 16 | 5 | Finalize scoring, negatives, reports, defense matrix |
| 17 | 6 | Docs, changelog, release |
| 18 | 7 | Kyo product improvement pass, stale-count refresh, final assumption check |

---

## Session Contract Template

Each Claude Code session should begin by pasting the relevant session contract from `TASK_PROMPTS.md`. The contract specifies: what phase you're in, what files exist, what the gate is, and what not to touch. This keeps sessions self-contained and prevents context drift.
