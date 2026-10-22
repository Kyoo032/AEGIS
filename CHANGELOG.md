# Changelog

## Unreleased

### Attack coverage

- completed OWASP agentic ASI01 through ASI10 coverage: added `asi08_cascading_failure` (12 payloads) and `asi10_rogue_agent` (14 payloads), with rules, rubrics, and OWASP mapping (PR #13)
- expanded `asi07_inter_agent` (+8), `llm01_prompt_inject` (+6 indirect-injection payloads), and `mcp06_cmd_injection` (+7 spoofing payloads)
- current corpus: 17 modules, 238 payloads with the default tool profile (235 in YAML plus 3 generated encoded variants); the new modules have not been baselined yet
- bundled configs cap payloads per module (`attacks.payloads_per_module`: 10, or 5 in the hosted template), so default scans run at most 170, 150, and 15 payloads for `config.yaml`, `config.local_single_qwen.yaml`, and `config.hosted.yaml`. The cap keeps the first payloads in file order, so with `config.yaml` none of the 21 negative controls run and the later payloads of larger modules (for example the ASI07 impersonation and relay payloads and the MCP06 spoofing payloads) are skipped

### Local Ollama execution

- switched the local Ollama path used by AEGIS from `POST /api/generate` to `POST /api/chat` with `think: false` for Qwen-backed runs
- added [config.local_single_qwen.yaml](aegis/config.local_single_qwen.yaml) for one-model local validation on tight VRAM
- validated single-model execution against `qwen3.5:0.8b`

### Fresh baseline evidence

- completed a fresh local baseline scan on April 21, 2026
- current live baseline artifact: `reports/baseline.json` (local run output, gitignored)
- current live corpus: 15 modules, 191 payloads
- current live baseline ASR: `144/191 = 0.7539`

### Testing

- full pytest gate passes with dashboard extras installed:
  - `uv run --extra dashboard pytest -s --cov=aegis --cov-report=term-missing --cov-fail-under=80`
  - result at the April 21 run: `751 passed`, `88.80%` coverage
  - result after the ASI08/ASI10 merge: `907 passed`, `88%` coverage
- `uv run ruff check .` passes

### Documentation

- refreshed [README.md](README.md) with the current live local-run posture
- rewrote [FINDINGS.md](docs/FINDINGS.md) around the April 21 baseline
- rewrote [METHODOLOGY.md](docs/METHODOLOGY.md) to describe the validated single-model local path
- updated [DEFENSE_EVALUATION.md](docs/DEFENSE_EVALUATION.md) to distinguish the live baseline lane from the Phase 5 matrix lane

### Known limitations

- `tests/test_orchestrator.py` and `tests/test_docker_smoke.py` are excluded from the default pytest run through `addopts` in `pyproject.toml`. Run without that exclusion, 5 of the 19 orchestrator tests fail when no Ollama server is running, because the default config enables the LLM judge with `judge_hard_fail`
- single-model local Qwen runs still show intermittent LLM-judge parse failures, so rule-based evidence remains the more stable signal for low-VRAM local validation

## v1.0.0 — 2026-02-26

Initial public AEGIS release with the original core attack set, defense modules, HTML reporting, and CI coverage gate.
