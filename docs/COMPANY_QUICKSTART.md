# AEGIS 10-Minute Company Quickstart

AEGIS is for AI teams building agents, MCP servers, RAG systems, and tool-using assistants. Use this Linux/WSL-first flow before a pilot, customer rollout, or internal launch review.

## 1. Install On Linux/WSL

```bash
git clone https://github.com/Kyoo032/AEGIS.git
cd AEGIS
uv sync --extra dev --extra dashboard
uv run aegis guide
```

Direct Linux/WSL runs read process environment variables. They do not read `.env` by default unless you explicitly source one.

## 2. Run A Baseline

Use the checked-in local config for a first scan:

```bash
uv run aegis scan \
  --config aegis/config.local_single_qwen.yaml \
  --format json \
  --output reports/company-baseline
```

Open `reports/company-baseline/baseline.json`.

## 3. Use A Hosted Provider

Copy the hosted template and set the provider fields:

```bash
cp aegis/config.hosted.yaml aegis/config.company-provider.yaml
```

For OpenAI or an OpenAI-compatible gateway:

```bash
export OPENAI_API_KEY=<your-key>
uv run aegis scan \
  --config aegis/config.company-provider.yaml \
  --output reports/company-hosted
```

For Anthropic, use `ANTHROPIC_API_KEY` and `mode: anthropic`. For Hugging Face, use `HF_TOKEN` and `mode: hf_inference`. For a company gateway, set `api_key_env` to a company-specific env var such as `ACME_LLM_API_KEY`.

Never paste raw API keys into YAML, reports, logs, tickets, or committed files.

## 4. Interpret The Result

| Signal | What to do |
|---|---|
| Exit code `0` | No successful attacks were detected in this run. Keep the report as a baseline. |
| Exit code `2` | The scan completed and found vulnerabilities. Review findings before launch. |
| Exit code `1` | Fix setup, config, provider, or report-rendering errors and rerun. |

## 5. Focus On Your Architecture

```bash
# Tool misuse and MCP boundaries
uv run aegis attack --module asi02_tool_misuse --output reports/asi02-tool-misuse
uv run aegis attack --module mcp06_cmd_injection --output reports/mcp06-cmd-injection

# Prompt injection and data disclosure
uv run aegis attack --module llm01_prompt_inject --output reports/llm01-prompt-inject
uv run aegis attack --module llm02_data_disclosure --output reports/llm02-data-disclosure
```

## 6. Test A Guardrail

```bash
uv run aegis defend \
  --defense tool_boundary \
  --output reports/tool-boundary
```

Use `matrix` when you want baseline, individual defenses, and layered defenses in one run:

```bash
uv run aegis matrix \
  --format json \
  --output reports/company-matrix
```

## 7. Share Evidence

Use the JSON report for CI and internal audit. Render HTML for review meetings:

```bash
uv run aegis report \
  --input reports/company-baseline/baseline.json \
  --format html \
  --output reports/company-baseline/baseline.html
```

## Later Packaging With Docker

Docker is a packaging path after the direct Linux/WSL workflow is stable. When you package with Docker, keep the same env-only secret contract and confirm generated reports do not contain raw API keys.
