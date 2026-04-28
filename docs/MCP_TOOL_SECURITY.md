# MCP And Tool Security Guide

Agent risk often appears outside the model prompt. AEGIS focuses on the agentic surfaces where real systems fail: tools, MCP servers, memory, RAG, approval flows, and delegated identity.

## What AEGIS Tests

| Surface | Typical failure | Relevant modules |
|---|---|---|
| Tool calls | The agent invokes a dangerous tool from attacker-controlled input. | `asi02_tool_misuse`, `asi05_code_exec` |
| MCP command handling | Parameters cross a trust boundary and become commands or file paths. | `mcp06_cmd_injection` |
| Supply chain | External docs, packages, or tool metadata steer behavior. | `asi04_supply_chain` |
| Memory and RAG | Poisoned context is treated as trusted instruction. | `asi06_memory_poison`, `llm01_prompt_inject` |
| Identity and approval | The agent accepts delegated authority without verification. | `asi03_identity_privilege`, `asi_hitl` |

## Minimum Company Controls

- Keep tool permissions narrow by default.
- Validate tool arguments before execution, not after model generation.
- Treat MCP server manifests as security-relevant artifacts.
- Block new or changed tools unless reviewed.
- Separate read-only tools from network, email, code execution, and write tools.
- Log prompts, tool calls, tool outputs, and defense decisions for audit.
- Run AEGIS before changing tools, providers, RAG corpora, or system prompts.

## A Practical Gate

1. Run `aegis scan` to establish baseline risk.
2. Run focused modules for your highest-risk tool families.
3. Add a guardrail such as `tool_boundary`, `mcp_integrity`, or `permission_enforcer`.
4. Run `aegis matrix` and compare attack success rate against the baseline.
5. Keep the report with the release evidence.
