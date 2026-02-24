# Day 6 Baseline Run

- Executed at: 2026-02-24T06:13:58.191956+00:00
- Run manifest: `reports/day6_run_manifest_20260224T061357Z.json`
- Baseline mode: undefended agent baseline, `provider.mode=offline`, scorers = `rule_based` + `llm_judge`
- Judge note: `llm_judge` attempted network calls but sandbox blocked outbound sockets (`Operation not permitted`), so the scorer fell back to safe defaults per implementation.

## Day 1-5 Quick Debug (Pre-Run)

Checks:
- Config and profiles load: `default`, `hardened`, `minimal`, `supply_chain` present.
- Day 5 evidence present:
  - `docs/DAY5_LIVE_RUN.md`
  - `reports/day5_live_report_*.json`
  - `reports/day5_live_results_*.jsonl`
- Core module loading verified in orchestrator:
  - Core 7: `asi01_goal_hijack`, `asi02_tool_misuse`, `asi04_supply_chain`, `asi05_code_exec`, `asi06_memory_poison`, `mcp06_cmd_injection`, `llm01_prompt_inject`
  - Extended: core 7 + `llm02_data_disclosure`

Quick smoke tests:
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/pytest tests/test_attacks/test_asi05.py tests/test_attacks/test_asi06.py tests/test_attacks/test_mcp06.py tests/test_testbed/test_agent.py::TestDefaultAgentHealthCheck tests/test_testbed/test_agent.py::TestDefaultAgentProfiles tests/test_eval/test_pipeline.py`
- Result: `32 passed in 1.38s`

## Backend Day 6 Verification

- `input_validator` implemented with:
  - instruction hierarchy/prompt override detection
  - malicious pattern filtering
  - encoded payload detection (base64/hex/rot13 indicators)
  - input length limiting
- `output_filter` implemented with:
  - PII/exfil pattern detection (email/url/path/ssn/phone)
  - strict blocking or redaction mode
- Agent wiring completed:
  - pre-LLM input inspection
  - post-generation output filtering
  - runtime toggling via `enable_defense()` / `disable_defense()`

Defense test run:
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/pytest tests/test_defenses/test_input_validator.py tests/test_defenses/test_output_filter.py tests/test_testbed/test_agent.py tests/test_reporting/test_report_generator.py`
- Result: `66 passed, 1 warning in 1.92s`

## Security Day 6 Baseline Results

### Core-7 Baseline (Day 6 Gate Scope)

- Results JSONL: `reports/day6_core7_baseline_results_20260224T061357Z.jsonl`
- Report JSON: `reports/day6_core7_baseline_report_20260224T061357Z.json`
- Report HTML: `reports/day6_core7_baseline_report_20260224T061357Z.html`
- Health: `reports/day6_core7_baseline_health_20260224T061357Z.json`
- Total attacks: 68
- Successful attacks: 1
- ASR: 0.014705882352941176
- OWASP categories present: `ASI01`, `ASI02`, `ASI04`, `ASI05`, `ASI06`, `LLM01`, `MCP06`

### Extended Baseline (Core-7 + Extras)

- Results JSONL: `reports/day6_extended_baseline_results_20260224T061357Z.jsonl`
- Report JSON: `reports/day6_extended_baseline_report_20260224T061357Z.json`
- Report HTML: `reports/day6_extended_baseline_report_20260224T061357Z.html`
- Health: `reports/day6_extended_baseline_health_20260224T061357Z.json`
- Total attacks: 78
- Successful attacks: 1
- ASR: 0.01282051282051282
- OWASP categories present: `ASI01`, `ASI02`, `ASI04`, `ASI05`, `ASI06`, `LLM01`, `LLM02`, `MCP06`

## Payload Tuning Note

Low-performing payload tuning was reviewed during this debug-oriented Day 6 run and deferred for a live-network scorer pass (to avoid optimizing against offline/sandbox artifacts). Candidate modules for next tuning pass are listed in the baseline reports with lowest ASR.
