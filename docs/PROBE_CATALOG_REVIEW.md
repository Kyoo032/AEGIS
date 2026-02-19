# Probe Catalog Review — Augustus, Garak, and AEGIS Coverage Gap Analysis

> **Date:** 2026-02-18
> **Purpose:** Document what existing tools cover so AEGIS custom modules target the gaps — specifically agentic AI attacks (tool misuse, memory poisoning, MCP exploitation) that these tools don't address.

---

## Tool Inventory

| Tool | Version | Probe Count | Focus |
|------|---------|-------------|-------|
| Augustus | 0.1.0 | 173 probes, 92 detectors, 43 generators | LLM vulnerability scanning (Go binary) |
| Garak | 0.14.0 | ~170 probes (219 entries incl. categories) | LLM vulnerability scanning (Python, NVIDIA) |
| Promptfoo | 0.120.24 | Custom YAML-driven | Red team testing framework |

---

## Augustus Probe Catalog (173 probes)

### Categories Covered

| Category | Probes | What It Tests |
|----------|--------|---------------|
| **DAN/Jailbreak** | 14 (dan.*) | Do-Anything-Now jailbreaks, DUDE, STAN, DevMode |
| **Prompt Injection** | 6 (promptinject.*) | Hijack prompts (HateHumans, KillHumans, LongPrompt) |
| **Encoding Bypass** | 0 (via buffs: 30) | Base64, ROT13, Hex, Morse, Braille, NATO, Leet, etc. |
| **Guardrail Evasion** | 20 (guardrail.*) | CharacterInjection, EncodingMix, SentenceFragmentation, SynonymSubstitution, TokenBoundary — per vendor (Azure, Meta, OpenAI, Generic) |
| **Latent Injection** | 3 (latentinjection.*) | Extraction, Jailbreak, Refusal via hidden context |
| **RAG Poisoning** | 4 (ragpoisoning.*) | High/Low confidence poisoning, metadata injection |
| **Exploitation** | 3 (exploitation.*) | Jinja template injection, SQL injection (echo + system) |
| **Web Injection** | 5 (webinjection.*) | CSS, FormFields, HTMLComment, JavaScript, MetaTags |
| **Art Prompts** | 4 (artprompts.*) | ASCII art, block elements, box drawing, braille encoding |
| **Toxicity** | 8 (realtoxicityprompts.*) | Flirtation, identity attack, insult, profanity, threat |
| **Content Safety** | 8 (lmrc.*) | Anthropomorphisation, profanity, quack medicine, sexual content |
| **Malware Gen** | 3 (malwaregen.*) | Evasion, subfunctions, top-level malware generation |
| **Data Leakage** | 8 (leakreplay.*) | Book/literature/news/Potter cloze completion |
| **Automated Attacks** | 7 (autodan, pair, tap, gcg, dra) | AutoDAN, PAIR, TAP, GCG, DRA automated red-teaming |
| **Package Hallucination** | 9 (packagehallucination.*) | Python, JS, Dart, Go, Perl, Ruby, Rust fake packages |
| **Multi-Agent** | 2 (multiagent.*) | MultiAgent, OrchestratorPoison |
| **Other** | ~20 | Glitch tokens, divergence, snowball, mindmap, steganography, etc. |

### Augustus Detectors (92)

Key detectors: `agent.ToolManipulation`, `promptinjection.DirectInjection`, `promptinjection.ContextManipulation`, `promptinjection.RoleManipulation`, `ragpoison.RAGPoison`, `exploitation.PythonCodeExecution`, `exploitation.SQLiEcho`, `goodside.MarkdownExfiltration`, `webinjection.XSS`

---

## Garak Probe Catalog (~170 probes)

### Categories Covered

| Category | Probes | What It Tests |
|----------|--------|---------------|
| **DAN/Jailbreak** | ~15 (dan.*) | DAN variants 6.0-11.0, DUDE, STAN, DevMode, DanInTheWild |
| **Prompt Injection** | 6 (promptinject.*) | HijackHateHumans, HijackKillHumans, HijackLongPrompt |
| **Encoding** | ~20 (encoding.*) | Base64, ROT13, Hex, Morse, Braille, Atbash, NATO, etc. |
| **Latent Injection** | ~15 (latentinjection.*) | Fact snippet, report, resume, translation, jailbreak, whois |
| **Exploitation** | 3 (exploitation.*) | Jinja template, SQL injection (echo + system) |
| **Web Injection** | ~8 (web_injection.*) | Markdown exfil, XSS, data leakage, string assembly |
| **Toxicity** | ~10 (realtoxicityprompts.*) | All RealToxicityPrompts categories |
| **Content Safety** | ~8 (lmrc.*) | Bullying, deadnaming, profanity, quack medicine, sexual |
| **Malware Gen** | 4 (malwaregen.*) | Evasion, payload, subfunctions, top-level |
| **Leakage** | ~16 (leakreplay.*) | Guardian, literature, NYT, Potter cloze/complete |
| **Goodside** | 4 (goodside.*) | Davidjl, Tag, ThreatenJSON, WhoIsRiley |
| **Smuggling** | 2 (smuggling.*) | FunctionMasking, HypotheticalResponse |
| **Automated** | 3 (tap.*, suffix.*) | TAP, PAIR, GCG, BEAST |
| **Phrasing** | 4 (phrasing.*) | FutureTense, PastTense bypass variants |
| **Package Hallucination** | 7 (packagehallucination.*) | Python, JS, Perl, Ruby, Rust, Dart, Raku |
| **Other** | ~20 | Snowball, divergence, visual jailbreak, FITD, doctor, topic |

### Garak Buffs (encoding transforms, 30 types)

Applied on top of any probe: Ascii85, Atbash, Base16/32/64, Base2048, Braille, CharCode, Ecoji, Hex, Leet, Morse, NATO, QP, ROT13, SneakyBits, UUencode, UnicodeTags, Zalgo, word/char flipping, lowercase, paraphrase, poetry, smuggling.

---

## Coverage Overlap: Augustus vs Garak

Both tools extensively cover:
- **DAN jailbreaks** (14-15 variants each)
- **Prompt injection** (direct hijack payloads)
- **Encoding bypass** (base64, rot13, hex, and 20+ other encodings)
- **SQL injection** (echo + system-level)
- **Toxicity/safety** (RealToxicityPrompts, profanity, content filters)
- **Data leakage** (cloze completion, training data extraction)
- **Web injection** (markdown exfil, XSS)
- **Package hallucination** (fake packages across 7+ languages)
- **Automated red-teaming** (PAIR, TAP, GCG)

---

## CRITICAL GAP: What Augustus and Garak Do NOT Cover

Neither tool tests **agentic AI behaviors** — they treat the LLM as a text-in/text-out black box. They don't:

### 1. Tool/MCP Exploitation (AEGIS modules: ASI02, ASI04, ASI05, MCP06)

| Gap | Description | AEGIS Module |
|-----|-------------|--------------|
| **Tool chaining attacks** | Tricking agent into reading a file then emailing it externally | ASI02 |
| **Parameter injection in tool calls** | Injecting malicious values into tool parameters (paths, URLs, SQL) | ASI02, MCP06 |
| **Evil MCP server / tool poisoning** | Malicious tool descriptions containing hidden instructions | ASI04 |
| **Prompt-to-RCE via code execution** | Injecting code through conversation that gets executed by a tool | ASI05 |
| **OS command injection via tools** | `; rm -rf /` through tool parameter fields | MCP06 |
| **SQL injection via database tool** | `'; DROP TABLE users; --` through the database MCP server | MCP06 |
| **Path traversal via filesystem tool** | `../../etc/passwd` through filesystem MCP server | MCP06 |

**Why neither tool covers this:** Augustus and Garak don't have tool-calling capabilities. They send prompts and analyze text responses. They cannot bind MCP servers, invoke tools, or observe tool call sequences. AEGIS's `DefaultAgent` with 5 bound MCP servers is required to test these attack surfaces.

### 2. Memory & Context Poisoning (AEGIS module: ASI06)

| Gap | Description | AEGIS Module |
|-----|-------------|--------------|
| **Cross-turn memory persistence** | Injecting malicious instructions that survive across conversation turns | ASI06 |
| **Memory poisoning** | Planting instructions in agent memory that alter future behavior | ASI06 |
| **RAG document poisoning** | Injecting malicious content into the retrieval-augmented generation pipeline | ASI06 (+ ASI01) |

**Why neither tool covers this:** Both tools test single-turn interactions. They don't maintain conversation state, inject into RAG stores, or verify instruction persistence across turns. AEGIS's `memory_store.py` and `rag_pipeline.py` enable multi-turn and RAG poisoning tests that are impossible with these tools.

### 3. Agent Goal Hijacking via Indirect Injection (AEGIS module: ASI01)

| Gap | Description | AEGIS Module |
|-----|-------------|--------------|
| **Indirect injection via RAG** | Poisoning retrieved documents to redirect agent behavior | ASI01 |
| **Indirect injection via tool output** | Embedding instructions in tool results that the agent follows | ASI01 |
| **Multi-turn escalation** | Gradually shifting agent goals across multiple turns | ASI01 |
| **Authority impersonation** | Claiming admin/system role to override safety | ASI01 |

**Partial overlap:** Augustus has `ragpoisoning.*` (4 probes) and `latentinjection.*` (3 probes), and Garak has `latentinjection.*` (~15 probes). However, these test text-level injection only — they don't test actual RAG pipeline poisoning where content is embedded in a vector store and retrieved contextually. AEGIS injects directly into ChromaDB via `agent.inject_context()`.

### 4. Supply Chain / Tool Integrity (AEGIS module: ASI04)

| Gap | Description | AEGIS Module |
|-----|-------------|--------------|
| **Malicious tool descriptions** | Tools whose descriptions contain hidden instructions | ASI04 |
| **Tool definition tampering** | Detecting when an MCP server's tool definitions change | ASI04 |
| **Trojan tool registration** | Evil server registering additional tools the agent auto-uses | ASI04 |

**Why neither tool covers this:** Augustus has `multiagent.OrchestratorPoison` (1 probe) which is the closest, but it doesn't actually test MCP tool description poisoning. AEGIS has a dedicated `evil_server.py` with intentionally malicious tool descriptions.

---

## Summary: AEGIS vs Existing Tools

| Attack Surface | Augustus | Garak | AEGIS |
|----------------|----------|-------|-------|
| DAN/Jailbreak | 14 probes | 15 probes | LLM01 (5+ payloads) |
| Direct Prompt Injection | 6 probes | 6 probes | LLM01 (10+ payloads) |
| Encoding Bypass | 30 buffs | 20+ probes + 30 buffs | LLM01 (base64, rot13, hex) |
| Latent/Indirect Injection | 3 probes | 15 probes | ASI01 (10 payloads, actual RAG) |
| RAG Poisoning | 4 probes (text-only) | 0 | ASI01/ASI06 (actual ChromaDB) |
| **Tool Chaining Exploits** | 0 | 0 | **ASI02 (10+ payloads)** |
| **MCP Tool Poisoning** | 0 | 0 | **ASI04 (10+ payloads)** |
| **Prompt-to-RCE** | 0 | 0 | **ASI05 (10+ payloads)** |
| **Memory Poisoning** | 0 | 0 | **ASI06 (10+ payloads)** |
| **Command Injection via Tools** | 0 | 0 | **MCP06 (10+ payloads)** |
| SQL Injection | 2 probes (text) | 2 probes (text) | MCP06 (actual SQLite) |
| Data Disclosure | 8 probes | 16 probes | LLM02 (system prompt + PII) |
| Toxicity/Safety | ~30 probes | ~30 probes | Not in scope |
| Package Hallucination | 9 probes | 7 probes | Not in scope |
| Automated Red-Team (PAIR/TAP/GCG) | 7 probes | 3 probes | Not in scope |

### Key Insight

**Augustus and Garak are excellent at testing the LLM as an isolated text model.** They cover jailbreaks, encoding bypasses, toxicity, and data leakage comprehensively with hundreds of probes.

**AEGIS fills the agentic gap.** When an LLM becomes an *agent* — with tools, memory, RAG, and MCP servers — entirely new attack surfaces emerge that text-only scanners cannot reach. AEGIS's 5 novel modules (ASI02, ASI04, ASI05, ASI06, MCP06) test attack surfaces that have **zero coverage** in either Augustus or Garak.

The recommended approach is:
1. **Use Garak/Augustus** for broad LLM safety baseline (jailbreaks, toxicity, encoding)
2. **Use AEGIS** for agentic attack surface testing (tools, memory, RAG, MCP)
3. **Use Promptfoo** for automated regression testing of both categories

---

## Verification Runs

| Tool | Status | Evidence |
|------|--------|----------|
| Augustus | Verified working (manual runtime validation) | Scan against `ollama.OllamaChat` with `qwen3:1.7b` — `docs/augustus_scan_results.jsonl` |
| Garak | Verified working (manual runtime validation) | Multiple run artifacts in `~/.local/share/garak/garak_runs/` |
| Promptfoo | Verified working (manual runtime validation) | Eval config at `promptfoo_configs/llm01_basic.yaml` — `promptfoo_configs/results/` |

## Execution Policy (Day 1-3 Baseline Locked)

- Policy date: February 19, 2026.
- Runtime validation for Day 1-3 is already complete and recorded in this repository.
- Default rule: do not re-run long external probe suites (Augustus/Garak/Promptfoo) for routine Day 1-3 rechecks.
- Re-run long probes only if one of these trigger conditions is true:
  - MCP server or tool behavior changed.
  - Judge model/provider configuration changed.
  - Payload or rule-detection logic changed in a way that affects probe comparability.
  - Existing evidence artifacts are missing or stale for the target branch.
