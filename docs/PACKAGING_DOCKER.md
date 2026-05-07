# Packaging AEGIS with Docker Compose

Docker Compose is AEGIS's packaging option for reproducible deployment.
The direct Linux/WSL path (`uv run aegis scan`) remains the canonical development workflow.
Use Docker when you need a self-contained, portable run environment.

## Prerequisites

- Docker Engine 24+ with Docker Compose v2.27+
- Optional: NVIDIA Container Toolkit for GPU acceleration

## Profiles

| Profile | Services started | When to use |
|---------|-----------------|-------------|
| _(none)_ | `aegis` only | Hosted-provider scans (`openai_compat`, `anthropic`, `hf_inference`) |
| `local` | `aegis` + `ollama` + `ollama-init` | Local Ollama scans |
| `dashboard` | adds `dashboard` | Streamlit report viewer |

Profiles compose: `--profile local --profile dashboard` brings up everything.

## Flows

### Hosted-only scan (BYOK)

```sh
# Export your key — never put it in a committed file.
export OPENAI_API_KEY=sk-...
export AEGIS_PROVIDER_MODE=openai_compat

docker compose build aegis
docker compose run --rm aegis scan --format json --output /app/reports
```

Supported provider modes and their required env vars:

| `AEGIS_PROVIDER_MODE` | Env var |
|-----------------------|---------|
| `openai_compat` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `hf_inference` | `HF_TOKEN` |
| `ollama` | _(none — local service)_ |

If the required key is missing the scan exits before execution with a clear error that names the missing variable but never echoes the key value.

### Local Ollama scan

```sh
# Pull and start ollama, then pull the target model.
docker compose --profile local up -d ollama
docker compose --profile local run --rm ollama-init   # pulls qwen3.5:0.8b

# Confirm the model is present before scanning.
docker compose --profile local exec ollama ollama list

# Run the scan.
docker compose run --rm aegis scan --format json --output /app/reports
```

`AEGIS_PROVIDER_MODE` defaults to `auto`, which discovers the local ollama service automatically. Set `AEGIS_PROVIDER_MODE=ollama` to be explicit.

> **Important:** Always pull the model before scanning. Running a scan without the model results in a trivial offline-only run that is not representative of real LLM behaviour.

### GPU acceleration

Requires the NVIDIA Container Toolkit installed on the host.

```sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.gpu.yml \
  --profile local up -d ollama

docker compose --profile local run --rm ollama-init
docker compose run --rm aegis scan
```

### Dashboard

```sh
docker compose --profile dashboard up -d dashboard
# Browse http://127.0.0.1:8501
```

The dashboard mounts `./reports` read-only. Run scans first so reports are available.

### All-in-one (local + dashboard)

```sh
docker compose --profile local --profile dashboard up -d
# Watch logs
docker compose logs -f
```

## Custom config and model overrides

```sh
export AEGIS_CONFIG_PATH=/app/aegis/config.hosted.yaml
export AEGIS_TARGET_MODEL=gpt-4o-mini
export AEGIS_JUDGE_MODEL=gpt-4o
docker compose run --rm aegis scan
```

Override the Ollama model pulled by `ollama-init`:

```sh
export OLLAMA_MODELS="qwen2.5:3b llama3.2:3b"
docker compose --profile local run --rm ollama-init
```

## Secret-leak smoke

After any scan, run this to confirm no raw API keys leaked into reports:

```sh
grep -RInE \
  'sk-[A-Za-z0-9]{20,}|sk-ant-api[A-Za-z0-9\-]{20,}|hf_[A-Za-z0-9]{20,}' \
  reports/
# Should return no output.
```

The gated pytest (`RUN_DOCKER_TESTS=1 pytest tests/test_docker_smoke.py -s`) automates this check end-to-end.

## Cleanup

```sh
# Stop all services and remove the ollama model volume.
docker compose --profile local --profile dashboard down -v

# Remove built images.
docker rmi aegis-runtime:local aegis-dashboard:local 2>/dev/null || true
```

## Bumping the ollama image pin

The `ollama` and `ollama-init` services are pinned by digest. To update:

```sh
docker buildx imagetools inspect ollama/ollama:latest | grep "^Digest:"
# Edit docker-compose.yml: replace the sha256 in both image fields and update the comment date.
```
