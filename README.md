# AEGIS — Agentic Exploit & Guardrail Investigation Suite

Security testing framework for auditing agentic AI systems. Targets OWASP LLM Top 10 (2025), Agentic Top 10 (2026), and MCP Top 10 (2025).

## Quick Start

```bash
uv sync --dev
uv run pytest
uv run aegis --help
```

## Security Defaults (Migration Notes)

- `code_exec` MCP tool is now disabled by default (`testbed.security.code_exec_enabled: false`).
- HTTP MCP requests are strict allowlist by default (`testbed.security.http_allowlist` + private-network blocking).
- New hardening knobs live under `testbed.security` in `aegis/config.yaml`.
