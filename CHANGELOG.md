# Changelog

## Unreleased

### Local Ollama execution

- switched the local Ollama path used by AEGIS from `POST /api/generate` to `POST /api/chat` with `think: false` for Qwen-backed runs
- added [config.local_single_qwen.yaml](/home/kyo/AEGIS/aegis/config.local_single_qwen.yaml) for one-model local validation on tight VRAM
- validated single-model execution against `qwen3.5:0.8b`

### Fresh baseline evidence

- completed a fresh local baseline scan on April 21, 2026
- current live baseline artifact: [baseline.json](/home/kyo/AEGIS/reports/baseline.json)
- current live corpus: 15 modules, 191 payloads
- current live baseline ASR: `144/191 = 0.7539`

### Testing

- full pytest gate passes with dashboard extras installed:
  - `uv run --extra dashboard pytest -s --cov=aegis --cov-report=term-missing --cov-fail-under=80`
  - result: `751 passed`, `88.80%` coverage
- `uv run ruff check .` passes

### Documentation

- refreshed [README.md](/home/kyo/AEGIS/README.md) with the current live local-run posture
- rewrote [FINDINGS.md](/home/kyo/AEGIS/docs/FINDINGS.md) around the April 21 baseline
- rewrote [METHODOLOGY.md](/home/kyo/AEGIS/docs/METHODOLOGY.md) to describe the validated single-model local path
- updated [DEFENSE_EVALUATION.md](/home/kyo/AEGIS/docs/DEFENSE_EVALUATION.md) to distinguish the live baseline lane from the Phase 5 matrix lane

### Known limitations

- single-model local Qwen runs still show intermittent LLM-judge parse failures, so rule-based evidence remains the more stable signal for low-VRAM local validation

## v1.0.0 — 2026-02-26

Initial public AEGIS release with the original core attack set, defense modules, HTML reporting, and CI coverage gate.
