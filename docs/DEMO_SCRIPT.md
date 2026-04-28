# AEGIS Demo Script

Use this for a short company demo or launch recording.

## Setup

```bash
cp .env.example .env
# edit .env with OLLAMA_MODELS and AEGIS_TARGET_MODEL

docker compose --profile local up -d ollama
docker compose --profile local run --rm ollama-init
```

## Talk Track

1. AEGIS is a Docker-first red-team toolkit for teams shipping agents, MCP servers, and tool-using AI.
2. The first command is the guide:

```bash
docker compose --profile local run --rm aegis guide
```

3. Run a baseline scan:

```bash
docker compose --profile local run --rm aegis scan \
  --format json \
  --output /app/reports/demo-baseline
```

4. Explain exit code `2`: the scan completed and found vulnerabilities.
5. Open `reports/demo-baseline/baseline.json` and show attack success rate, OWASP grouping, findings, and recommendations.
6. Run one focused module:

```bash
docker compose --profile local run --rm aegis attack \
  --module asi02_tool_misuse \
  --output /app/reports/demo-asi02
```

7. Run a defense comparison:

```bash
docker compose --profile local run --rm aegis matrix \
  --format json \
  --output /app/reports/demo-matrix
```

## Close

AEGIS gives teams a repeatable way to find agentic AI risks before customers do: baseline, focus, defend, compare, and ship with evidence.
