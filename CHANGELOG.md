# Changelog

## v1.0.0 — 2026-02-26

Initial release of AEGIS (Agentic Exploit & Guardrail Investigation Suite).

### Attack Modules (8)

- `llm01_prompt_inject` — Direct/indirect prompt injection, jailbreaks, encoding bypasses
- `llm02_data_disclosure` — PII extraction, secret leakage, system prompt exfiltration
- `asi01_goal_hijack` — Agent goal redirection and system prompt override
- `asi02_tool_misuse` — Tool chaining exploits and parameter injection
- `asi04_supply_chain` — Evil MCP server injection, poisoned tool descriptions
- `asi05_code_exec` — Prompt-to-RCE via code execution MCP
- `asi06_memory_poison` — Cross-turn memory corruption, persistent instruction injection
- `mcp06_cmd_injection` — OS command injection, SQL injection, path traversal via MCP

### Defense Modules (5)

- `input_validator` — Prompt sanitization and pattern blocking (-65.52% ASR)
- `output_filter` — PII detection and exfiltration blocking
- `tool_boundary` — Tool allowlisting, parameter validation, rate limiting (-7.35% ASR)
- `mcp_integrity` — MCP manifest hash verification and poison detection
- `permission_enforcer` — Least-privilege per tool, cross-tool access control

Best layered combination: `input_validator + output_filter + tool_boundary` achieves 79.31% ASR reduction.

### Evaluation Pipeline

- Rule-based scorer with regex/pattern detection for all attack categories
- LLM judge scorer (Qwen3-1.7B via Ollama) with Pydantic output parsing
- Confidence-weighted disagreement resolution between scorers
- Attack Success Rate (ASR) metrics with per-category breakdown

### Agent Testbed

- `DefaultAgent` with LangChain + Ollama integration, multi-turn support, RAG, memory
- `MockAgent` for deterministic offline testing (no Ollama required)
- 6 MCP servers: filesystem, HTTP, email, database, code execution, evil (supply chain)
- Knowledge base subsystem with ChromaDB indexing, poisoning, and trust policies
- Exponential backoff retry logic for LLM calls

### CLI

- `aegis scan` — Baseline security scan
- `aegis attack` — Run specific attack modules
- `aegis defend` — Test individual defenses
- `aegis matrix` — Full attack-defense comparison matrix
- `aegis report` — Generate HTML/JSON reports from results

### Reporting

- HTML report generation via Jinja2 templates
- JSON structured output with OWASP and MITRE ATLAS mapping
- Schema validation for report and matrix artifacts

### Infrastructure

- GitHub Actions CI: lint (ruff), test (pytest, 80% coverage threshold), schema validation
- Integration test workflow for end-to-end pipeline validation
- 549 tests, 89% code coverage
- All dependencies pinned to exact versions

### Documentation

- METHODOLOGY.md — Evaluation methodology and scoring rationale
- FINDINGS.md — Baseline attack results and analysis
- DEFENSE_EVALUATION.md — Defense effectiveness and bypass analysis
