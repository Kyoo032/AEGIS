# AEGIS — 14-Day Development Plan

> **Strategic overview.** See [TASK_PROMPTS.md](TASK_PROMPTS.md) for detailed daily Claude Code prompts.
> See [claude.md](claude.md) for the authoritative technical specification (models, interfaces, repo structure).

---

## Phase 1: Foundation (Days 1–3)

**Goal:** Build the basic infrastructure that everything else depends on. By the end of Day 3, the testbed agent should be running, connected to all MCP servers, with RAG and memory capabilities, and ready to receive attacks. Attack base class, first attack module, and evaluation scaffolding should be functional.

| Day | Backend Lead | Security Lead | Done When |
|-----|-------------|---------------|-----------|
| 1 | Create repository structure. Write shared `models.py` with Pydantic data models (AttackPayload, AgentResponse, AttackResult, EvaluationResult, Finding, OWASPCategoryResult, SecurityReport). Write interface ABCs (`AttackModule`, `Scorer`, `Defense`, `AgentInterface`). Set up `config.yaml` + `config.py`. Install Ollama and pull Qwen3-4B (Q4_K_M) and Qwen3-1.7B models. Build basic LangChain agent stub that can receive a prompt and generate a response. | Install Augustus, Garak, and Promptfoo locally. Verify each tool runs against a simple test target. Read through Augustus probe catalog (210+ probes) and Garak probe catalog (160+) to understand coverage. Create `attacks/base.py` — convenience base class implementing AttackModule (YAML loading, iteration, result collection). Create YAML payload schema. Build `llm01_prompt_inject` module with 5+ payloads (direct injection, instruction override, encoding bypass, multi-language). Create `evaluation/rule_detector.py` — pattern-based detection rules. | Both people can clone the repo. Agent stub responds to a basic prompt. Attack module generates valid `AttackPayload` objects. Rule detector identifies injection patterns. |
| 2 | Build 5 FastMCP servers using FastMCP Python SDK: **(1) Filesystem** — `read_file`, `write_file`, `list_directory`, `delete_file` in a sandboxed directory. **(2) HTTP** — `fetch_url`, `post_request`. **(3) Email** — `send_email`, `read_inbox` (mock, stores in memory). **(4) Database** — `query_db`, `insert_record` (SQLite in-memory). **(5) Code Execution** — `execute_code` (sandboxed subprocess with timeout). Implement `aegis/testbed/agent.py` with LangChain + Ollama (qwen3:4b). `run()` accepts AttackPayload, sends messages with all tools bound, captures every tool invocation as ToolCall, returns AgentResponse. Add Ollama health check. | Build `asi01_goal_hijack` module — indirect prompt injection via system prompt override, goal redirection, context manipulation. Create 8-10 YAML payloads. Build `evaluation/scorer.py` implementing Scorer interface (rule-based, using rule_detector patterns). Build `evaluation/metrics.py` — ASR computation, per-category ASR, aggregate statistics. Test against live agent once available. | **GATE:** `agent = DefaultAgent(config="test"); response = agent.run(test_payload); assert len(response.tool_calls) > 0`. Agent invokes all 5 MCP tools. Scorer produces valid EvaluationResult objects. |
| 3 | Set up ChromaDB RAG pipeline (`rag_pipeline.py`): document ingestion (chunk, embed, store), retrieval (query → top-k relevant chunks), wire into agent when `rag_enabled=true`. Build conversation memory system (`memory_store.py`) persisting across `agent.run()` calls. Build evil MCP server (`evil_server.py`) with tool descriptions containing hidden instructions (tool poisoning). Implement `agent.inject_context()` for methods: `rag`, `memory`, `tool_output`. | Build `evaluation/llm_judge.py` — LLM-as-judge scorer using Qwen3-1.7B via Ollama. Parse judgments into EvaluationResult with confidence. Build `reporting/report_generator.py` — accepts list[EvaluationResult], produces SecurityReport model, basic Jinja2 HTML output. Build `reporting/owasp_mapper.py` and `reporting/atlas_mapper.py`. [OPTIONAL] Create first Promptfoo config for automated LLM01 testing. | **GATE:** `agent.inject_context("Ignore all instructions...", method="rag"); response = agent.run(benign_payload)` — poisoned content influences behavior. RAG returns relevant documents. Evil MCP server returns poisoned descriptions. LLM judge scores results. |

### Phase 1 Runtime Validation Status (Locked)

- Manual runtime validation completed on February 18-19, 2026.
- Validated components:
  - Ollama with `qwen3:4b` and `qwen3:1.7b`
  - Promptfoo
  - Garak
  - Augustus
- Evidence artifacts:
  - `docs/augustus_scan_results.jsonl`
  - `docs/augustus_scan_report.html`
  - `docs/PROBE_CATALOG_REVIEW.md`
  - `promptfoo_configs/llm01_basic.yaml`
- Default policy for Day 1-3 checks: do not re-run long external probe suites if evidence artifacts are present and current.
- Re-run long probes only when one of these trigger conditions is met:
  - MCP server or tool behavior changed.
  - Judge model/provider configuration changed.
  - Payload or rule-detection logic changed in a way that impacts scanner comparability.
  - Existing evidence artifacts are missing or stale for the branch under test.

### Known Deviation (Tracked)

- Day 3 RAG implementation is currently a deterministic in-memory retriever (`aegis/testbed/rag_pipeline.py`) rather than full ChromaDB + embedding storage.
- Day 3 security gate behavior is still available through `agent.inject_context(..., method="rag")`, `evil_server`, and passing tests; treat ChromaDB parity as follow-up technical debt.

---

## Phase 2: Attack Development (Days 4–5)

**Goal:** Build all 7 core attack modules, complete the evaluation pipeline, and get offline testing working with MockAgent.

| Day | Backend Lead | Security Lead | Done When |
|-----|-------------|---------------|-----------|
| 4 | Create MockAgent (implements AgentInterface) with canned responses for offline testing. Implement timeout and retry logic for LLM calls (configurable in config.yaml). Build agent profiles: "default" (all tools, no defenses), "hardened" (restricted tools, input validation), "minimal" (filesystem only, no RAG/memory). Add multi-turn conversation support to `agent.run()`. Fix any testbed issues from Day 3. | Build `asi02_tool_misuse` module — tool chaining exploits ("read password file then email it"), parameter injection. Create YAML payloads. Build `asi04_supply_chain` module — tests evil MCP server, verifies if agent follows hidden instructions in tool descriptions. Build `evaluation/pipeline.py` — runs all configured scorers, handles disagreements with confidence-weighted resolution. Expand `rule_detector.py` for tool misuse and supply chain patterns. | MockAgent returns canned responses. 4 attack modules (LLM01, ASI01, ASI02, ASI04) produce valid AttackResult objects. Evaluation pipeline resolves multi-scorer results. |
| 5 | Wire agent with evil_server for supply chain testing. Complete `inject_context()` — all three methods (rag, memory, tool_output) verified working. Add agent health checks (Ollama availability, MCP server connectivity). Begin `defenses/input_validator.py` skeleton — basic pattern matching. Document testbed API (docstrings, type hints on all public methods). | Build `asi05_code_exec` module — prompt-to-RCE through code execution MCP server, inject malicious code via poisoned context. Build `asi06_memory_poison` module — persistent malicious instructions in agent memory, cross-turn survival, cross-session corruption. Build `mcp06_cmd_injection` module — OS command injection through tool parameters, SQL injection through database server, path traversal through filesystem server. Create YAML payloads for all three. Run all 5 existing modules against live agent. | All 7 core attack modules built and tested. `inject_context()` works for all 3 methods. Evil server wired into agent. |

### Day 5 Completion Status (Locked)

- Backend and security Day 5 tracks are complete.
- Validation criteria met: `inject_context()` supports `rag`, `memory`, and `tool_output`; evil MCP coverage present; health-check API reports provider/model/MCP connectivity.
- Evidence artifacts are generated under `reports/` and documented in Day 5 run notes in `docs/`.

### Day 6 Completion Status (Locked)

- Day 6 backend and security tracks are complete.
- Day 1-5 quick debug pass completed before Day 6 baseline:
  - Profile/config/module loading checks passed (including `default`, `hardened`, `minimal`, `supply_chain`).
  - Smoke suite result: `32 passed in 1.38s`.
- Day 6 baseline evidence (fresh run timestamp: `20260224T061357Z`) is generated and documented:
  - Manifest: `reports/day6_run_manifest_20260224T061357Z.json`
  - Run notes: `docs/DAY6_BASELINE_RUN.md`
  - Core-7 baseline report: `reports/day6_core7_baseline_report_20260224T061357Z.json` and `.html`
  - Extended baseline report: `reports/day6_extended_baseline_report_20260224T061357Z.json` and `.html`
- Day 6 gate checks satisfied:
  - `input_validator` and `output_filter` are implemented and toggleable through `enable_defense()` / `disable_defense()`.
  - `input_validator.inspect("ignore previous instructions") -> (True, "injection detected")`.
  - `input_validator.inspect("what's the weather?") -> (False, "")`.
  - Core-7 baseline ASR collected with results for all 7 required OWASP categories.
  - HTML report template `aegis/reporting/templates/report.html.j2` renders with real baseline data.

---

## Phase 3: Defense & Baseline (Days 6–7)

**Goal:** Build the first two defenses, collect the complete undefended baseline, and sync both tracks before the defense hardening push.

| Day | Backend Lead | Security Lead | Done When |
|-----|-------------|---------------|-----------|
| 6 | Implement `defenses/input_validator.py` fully: instruction hierarchy enforcement (system prompt priority), known malicious pattern filtering, input length limiting. Must implement `apply()`, `remove()`, `inspect()`. Wire into agent: when active, `agent.run()` passes input through `inspect()` before LLM. Implement `defenses/output_filter.py`: PII detection, exfiltration pattern blocking, sensitive data redaction. Wire all defenses into `agent.enable_defense()` / `disable_defense()` API. | Run ALL 7 attack modules against the live agent (undefended baseline pass). Score all results through `pipeline.py` with both rule-based and llm_judge scorers. Create `reporting/templates/report.html.j2` — styled HTML report with executive summary, per-OWASP breakdown, individual findings, MITRE ATLAS references. Generate first real SecurityReport from baseline results. Tune low-performing payloads. [OPTIONAL] Run Garak baseline scan and Augustus broad scan for independent benchmark. | Baseline ASR collected for all 7 modules (undefended). 2 defenses (`input_validator`, `output_filter`) active and toggleable via `enable_defense()` / `disable_defense()`. First real SecurityReport generated from baseline data. |
| 7 | **Buffer & Sync day.** Pull develop. Resolve merge conflicts. Run `pytest tests/test_integration.py` — fix failures as a team. Review: does baseline SecurityReport have data for all 7 modules? If ahead: document testbed API, create additional agent profiles (easy/medium/hardened). | **Buffer & Sync day.** Pull develop. Resolve merge conflicts. Run integration test. If ahead: expand payload sets, tune low-performing attacks, run Promptfoo automated suite, run Proximity MCP scanner against MCP servers. | **END OF DAY:** Both tracks merged to develop. Integration test green. Baseline ASR collected for all 7 modules. No blocking issues between tracks. |

---

## Phase 4: Defense Hardening (Days 8–9)

**Goal:** Build the remaining 3 defenses and measure the full attack-defense matrix (7 attacks × 5 defenses + baseline + layered combinations).

| Day | Backend Lead | Security Lead | Done When |
|-----|-------------|---------------|-----------|
| 8 | Implement `defenses/tool_boundary.py`: tool call allowlisting (only permitted tool sequences), parameter validation (block suspicious parameters), rate limiting on tool calls. Notify Security Lead for immediate re-testing. | Re-run ALL 7 attack modules with `input_validator` defense active. Re-run ALL 7 with `output_filter` active. Re-run ALL 7 with `tool_boundary` active. Record which attacks bypass each defense. Adapt payloads to evade defenses — document bypass techniques. | 3 defenses deployed and tested. ASR delta measured for each defense vs baseline. Bypass techniques documented. |
| 9 | Implement `defenses/mcp_integrity.py`: tool description hash verification (detect tool poisoning), MCP server definition change detection, alert on unexpected tool additions. Implement `defenses/permission_enforcer.py`: least-privilege enforcement per tool, read-only vs read-write scoping, cross-tool access control. Test all 5 defense enable/disable flows end-to-end. | Re-run ALL 7 attacks with `mcp_integrity` and `permission_enforcer` active. Build full attack-defense results matrix (7 attacks × 5 defenses + baseline). Test layered defenses (multiple defenses active simultaneously). Update `docs/DEFENSE_EVALUATION.md` with bypass techniques found. | All 5 defenses deployable via `enable_defense()` / `disable_defense()`. Full 7×5+ attack-defense matrix measured. Layered defense results collected. |

---

## Phase 5: Orchestrator & Reports (Day 10)

**Goal:** Wire together the complete pipeline and produce reports from real data.

| Day | Backend Lead | Security Lead | Done When |
|-----|-------------|---------------|-----------|
| 10 | Implement `orchestrator.py` fully — `AEGISOrchestrator` with `run_baseline()`, `run_with_defense(defense_name)`, `run_full_matrix()`. Wire together: agent, attacks, scorers, reporter. Uses `load_config()`. Begin `cli.py` with Typer commands: `aegis scan` (full baseline), `aegis attack --module asi01` (specific module), `aegis defend --defense input_validator` (specific defense). | Run full attack-defense matrix through `orchestrator.run_full_matrix()`. Generate comparison reports for each defense configuration. Finalize `reporting/templates/report.html.j2` with defense comparison table. Add PDF generation (weasyprint or similar). Begin `docs/FINDINGS.md` — key results with ASR tables, baseline vs defended. | `orchestrator.run_full_matrix()` completes successfully. CLI commands `aegis scan`, `aegis attack`, `aegis defend` all functional. HTML + JSON reports generate from real data. |

---

## Phase 6: Publication (Days 11–13)

**Goal:** Complete CLI, CI/CD, documentation, and ensure the project is production-ready.

| Day | Backend Lead | Security Lead | Done When |
|-----|-------------|---------------|-----------|
| 11 | Complete `cli.py` — all commands fully functional: `aegis scan`, `aegis attack --module`, `aegis defend --defense`, `aegis report --format html --output ./reports/`, `aegis matrix`. | Complete `docs/FINDINGS.md` — ASR per category, baseline vs defended, attack technique writeups. Complete `docs/METHODOLOGY.md` — research approach, threat model, test environment description. | CLI polished with all commands. Key documentation drafted. |
| 12 | Create `.github/workflows/ci.yml` — run pytest on push to develop/main. Create `.github/workflows/integration.yml` — run integration test. Write `README.md`: project description, architecture diagram (Mermaid), installation, quickstart. [OPTIONAL] Docker compose file for Ollama + AEGIS. | Complete `docs/DEFENSE_EVALUATION.md` — defense comparison analysis, bypass techniques. Create `promptfoo_configs/basic_redteam.yaml` for automated red team runs. Prepare payload dataset in `datasets/` directory. Cross-review Backend Lead's README for technical accuracy. | CI/CD pipeline is green. All documentation drafted and reviewed. README complete. |
| 13 | Test installation from scratch: fresh clone → `uv sync` → `aegis scan` works. Quick-start examples in README. Pin dependency versions in `pyproject.toml`. Run full `pytest` suite — target 80%+ coverage. `ruff check aegis/` — fix all lint issues. | Final QA on all report outputs (JSON, HTML, PDF). Sample report committed to repo. Verify no secrets/credentials in any committed file. [OPTIONAL] Blog post draft. Cross-review documentation with Backend Lead. | Fresh clone → install → scan works. 80%+ test coverage. Clean `ruff check`. No secrets committed. All report outputs verified. |

### Phase 6 Completion Status (Locked)

- Days 11-13 publication work complete.
- Day 12 deliverables:
  - `.github/workflows/ci.yml`: ruff lint + pytest --cov --cov-fail-under=80
  - `.github/workflows/integration.yml`: integration + CLI tests + schema validation
  - `README.md` rewritten with Mermaid architecture diagram, module tables, 5 quick start examples
  - `promptfoo_configs/basic_redteam.yaml`: 13 tests across LLM01/ASI01/ASI02/MCP06
  - `datasets/payloads/`: 8 JSON payload files (83 total payloads)
  - `docs/DEFENSE_EVALUATION.md` expanded with per-defense bypass analysis and recommendations matrix
- Day 13 deliverables:
  - All dependencies pinned to exact `==X.Y.Z` versions
  - `ruff check aegis/` clean (0 errors)
  - 89% test coverage (threshold: 80%)
  - Fresh clone install verified: `uv sync` → `aegis --help` → `pytest --cov` all pass
  - `OWASPMapping` model added to align Pydantic with JSON schema
  - Sample report committed: `reports/sample_baseline_report.json` + `.html`
  - Security audit: no hardcoded secrets, all payloads use safe example domains
- Gate checks satisfied:
  - `ruff check aegis/` → All checks passed
  - `pytest --cov --cov-fail-under=80` → 89% coverage, 482 passed
  - `aegis --help` → exit 0
  - `validate_reports.py --schema report` → OK
  - No secrets found via grep scan

---

## Phase 7: Release (Day 14) — LOCKED

**Goal:** Ship AEGIS v1.0.

| Day | Everyone | Done When |
|-----|----------|-----------|
| 14 | Pull develop. All tests pass (`pytest` green, `ruff check` clean). Run `aegis scan` end-to-end — verify JSON + HTML reports. Run `aegis matrix` for full attack-defense comparison. Review README — does a stranger understand what this is and how to use it? Review all `docs/` files: METHODOLOGY, FINDINGS, DEFENSE_EVALUATION. Add LICENSE file. Pin dependency versions. Verify no secrets committed. Create `CHANGELOG.md` with v1.0 highlights. Verify clean install: fresh clone → `uv sync` → `aegis scan` works. Tag v1.0: `git tag -a v1.0 -m "AEGIS v1.0 — Initial release"`. Merge develop → main. [OPTIONAL] Upload payload dataset to HuggingFace. Announce on LinkedIn, relevant forums. Submit to OWASP working groups if appropriate. | **AEGIS v1.0 is shipped:** repo is public, documentation is complete, reports generate cleanly, a stranger can clone and run a complete scan without asking questions. |

- Gate checks satisfied:
  - `ruff check aegis/` → All checks passed
  - `pytest --cov --cov-fail-under=80` → 89.15% coverage, 549 passed
  - `aegis --help` → exit 0
  - LICENSE file created (MIT)
  - CHANGELOG.md created with v1.0 highlights
  - All dependencies pinned to exact versions (no unpinned ranges)
  - No secrets found via grep scan
  - README reviewed — comprehensive with architecture, install, CLI, profiles
  - docs/ reviewed — METHODOLOGY.md, FINDINGS.md, DEFENSE_EVALUATION.md complete
  - Version bumped to 1.0.0

---

## Stretch Goals (Time Permitting)

These modules are descoped from the core 14-day plan per [claude.md](claude.md):

| Module | OWASP ID | Description |
|--------|----------|-------------|
| `mcp01_token_leak` | MCP01 | API key/token extraction from tool descriptions and error messages |
| `llm02_data_disclosure` | LLM02 | System prompt extraction, training data extraction, PII leakage |
| `asi03_privilege_abuse` | ASI03 | Privilege escalation through agent capabilities |

**Best time to add:** During buffer day (Day 7) or publication phase (Days 11-13) if core work is ahead of schedule. Each module follows the same `AttackModule` interface and YAML payload pattern.

---

## External Tools

| Tool | Purpose | Status |
|------|---------|--------|
| **Promptfoo** | Automated red team testing framework | Installed |
| **Garak** | LLM vulnerability scanning (160+ probes) | Installed |
| **Augustus** | LLM vulnerability probes (210+ probes) | Installed |
| **Proximity** | MCP server scanning | To install |

These tools supplement AEGIS's custom attack modules. They run independently and their results can be compared with AEGIS findings for validation. Marked as optional enrichment in the daily schedule — core AEGIS functionality never depends on them.
