# AEGIS Launch Copy

## Short Description

AEGIS is an open-source red-team toolkit for AI teams building agents, MCP servers, RAG systems, and tool-using applications.

## One-Liner

Run adversarial agent security scans locally with Docker, then use structured reports to harden tools, memory, RAG, and guardrails before launch.

## Audience

- Companies building internal or customer-facing AI agents
- Teams adopting MCP servers or tool-calling frameworks
- Security engineers reviewing agentic AI releases
- Founders and platform teams who need local evidence before a hosted pilot

## Core Message

Modern AI failures often happen in the agent scaffolding around the model. AEGIS tests the paths that matter: tool misuse, command injection, memory poisoning, RAG poisoning, supply-chain context, delegated identity, and approval flows.

## Launch Post

AI teams are moving from chatbots to agents with tools, MCP servers, memory, and RAG. That creates a new security surface.

AEGIS is an OSS-first red-team toolkit for agentic AI. It runs locally with Docker, attacks your target model and agent harness, scores the transcript, and produces JSON/HTML reports you can use in release reviews and CI.

Start with Docker, run a baseline, inspect findings, add guardrails, and rerun a defense matrix before shipping.

## Calls To Action

- Try the Docker quickstart in the README.
- Run `aegis guide` for the first workflow.
- Use the company quickstart for an internal launch review.
- Share focused findings for agents, MCP tools, and RAG pipelines.
