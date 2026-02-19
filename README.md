# AEGIS — Agentic Exploit & Guardrail Investigation Suite

Security testing framework for auditing agentic AI systems. Targets OWASP LLM Top 10 (2025), Agentic Top 10 (2026), and MCP Top 10 (2025).

## Quick Start

```bash
uv sync --dev
uv run pytest
uv run aegis --help
```

## Validation Policy

- Day 1-3 runtime validation was completed manually on February 18-19, 2026.
- Verified components: Ollama models `qwen3:4b` and `qwen3:1.7b`, plus Promptfoo, Garak, and Augustus.
- Baseline evidence:
  - `docs/augustus_scan_results.jsonl`
  - `docs/augustus_scan_report.html`
  - `docs/PROBE_CATALOG_REVIEW.md`
  - `promptfoo_configs/llm01_basic.yaml`
- Default policy: avoid re-running long external probe suites for routine Day 1-3 checks.
- Re-run long probes only when one of these conditions is true:
  - MCP server or tool behavior changed.
  - Judge model/provider configuration changed.
  - Payload or rule-detection logic changed in a way that affects probe comparability.
  - Existing evidence artifacts are missing or stale for the target branch.

## Security Defaults (Migration Notes)

- `code_exec` MCP tool is now disabled by default (`testbed.security.code_exec_enabled: false`).
- HTTP MCP requests are strict allowlist by default (`testbed.security.http_allowlist` + private-network blocking).
- New hardening knobs live under `testbed.security` in `aegis/config.yaml`.
