# AEGIS Demo Script

Use this for a short company demo or launch recording. The demo is Linux/WSL-first; Docker is packaging work after the direct path is stable.

## Setup

```bash
git clone https://github.com/Kyoo032/AEGIS.git
cd AEGIS
uv sync --extra dev --extra dashboard
```

For a local Ollama model, make sure Ollama is running on the host and pull the model you want to test:

```bash
ollama pull <your-model>:<tag>
export AEGIS_TARGET_MODEL=<your-model>:<tag>
```

For hosted providers, export the relevant key in the shell:

```bash
export OPENAI_API_KEY=<your-openai-or-compatible-key>
# or: export ANTHROPIC_API_KEY=<your-anthropic-key>
# or: export HF_TOKEN=<your-hugging-face-token>
```

## Talk Track

1. AEGIS is a Linux/WSL-first red-team toolkit for teams shipping agents, MCP servers, RAG systems, and tool-using AI.
2. The first command is the guide:

```bash
uv run aegis guide
```

3. Run a baseline scan:

```bash
uv run aegis scan \
  --config aegis/config.local_single_qwen.yaml \
  --format json \
  --output reports/demo-baseline
```

4. Explain exit code `2`: the scan completed and found vulnerabilities.
5. Open `reports/demo-baseline/baseline.json` and show attack success rate, OWASP grouping, findings, and recommendations.
6. Run one focused module:

```bash
uv run aegis attack \
  --module asi02_tool_misuse \
  --output reports/demo-asi02
```

7. Run a defense comparison:

```bash
uv run aegis matrix \
  --format json \
  --output reports/demo-matrix
```

8. Optional: open the local dashboard.

```bash
uv run streamlit run dashboard/app.py
```

## Close

AEGIS gives teams a repeatable way to find agentic AI risks before customers do: baseline, focus, defend, compare, and ship with evidence. API keys stay in environment variables or temporary dashboard input; they do not belong in configs, reports, logs, tickets, or committed files.
