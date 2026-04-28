# AEGIS 10-Minute Company Quickstart

AEGIS is for AI teams building agents, MCP servers, RAG systems, and tool-using assistants. Use this flow before a pilot, customer rollout, or internal launch review.

## 1. Start With Docker

```bash
git clone https://github.com/Kyoo032/AEGIS.git
cd AEGIS
cp .env.example .env
```

Edit `.env` and choose your local model:

```dotenv
OLLAMA_MODELS=<your-model>:<tag>
AEGIS_TARGET_MODEL=<your-model>:<tag>
# Optional: AEGIS_JUDGE_MODEL=<judge-model>:<tag>
```

Then start the local provider and scanner:

```bash
docker compose --profile local up -d ollama
docker compose --profile local run --rm ollama-init
docker compose --profile local run --rm aegis guide
```

## 2. Run A Baseline

```bash
docker compose --profile local run --rm aegis scan \
  --format json \
  --output /app/reports/company-baseline
```

Open `reports/company-baseline/baseline.json` on the host.

## 3. Interpret The Result

| Signal | What to do |
|---|---|
| Exit code `0` | No successful attacks were detected in this run. Keep the report as a baseline. |
| Exit code `2` | The scan completed and found vulnerabilities. Review findings before launch. |
| Exit code `1` | Fix setup, config, provider, or report-rendering errors and rerun. |

## 4. Focus On Your Architecture

```bash
# Tool misuse and MCP boundaries
docker compose --profile local run --rm aegis attack --module asi02_tool_misuse

docker compose --profile local run --rm aegis attack --module mcp06_cmd_injection

# Prompt injection and data disclosure
docker compose --profile local run --rm aegis attack --module llm01_prompt_inject

docker compose --profile local run --rm aegis attack --module llm02_data_disclosure
```

## 5. Test A Guardrail

```bash
docker compose --profile local run --rm aegis defend \
  --defense tool_boundary \
  --output /app/reports/tool-boundary
```

Use `matrix` when you want baseline, individual defenses, and layered defenses in one run:

```bash
docker compose --profile local run --rm aegis matrix \
  --format json \
  --output /app/reports/company-matrix
```

## 6. Share Evidence

Use the JSON report for CI and internal audit. Render HTML for review meetings:

```bash
docker compose run --rm aegis report \
  --input reports/company-baseline/baseline.json \
  --format html \
  --output reports/company-baseline/baseline.html
```
