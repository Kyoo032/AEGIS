ARG PYTHON_IMAGE=python:3.11@sha256:e33bce801053f329b16f5cf139453277cd23ab68f75478b4eeff102a4654aed7
ARG PYTHON_SLIM_IMAGE=python:3.11-slim@sha256:92c262cbb2e99cdc16218338d74fbe518055c13d224d942708f70f8042ff6d18

# Stage 1 — Builder: install core CLI dependencies and package sources.
FROM ${PYTHON_IMAGE} AS builder

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --no-dev --extra local --frozen

COPY aegis/ aegis/
COPY datasets/ datasets/
COPY schemas/ schemas/
COPY dashboard/ dashboard/

# Stage 2 — Dashboard builder: layer dashboard dependencies on top of the core venv.
FROM builder AS dashboard-builder

RUN uv pip install --python .venv/bin/python ".[dashboard]"

# Stage 3 — Shared runtime base: non-root execution and writable mounts only.
FROM ${PYTHON_SLIM_IMAGE} AS runtime-base

RUN groupadd --gid 1000 aegis && \
    useradd --uid 1000 --gid aegis --create-home aegis && \
    mkdir -p /app/reports /tmp/aegis_fs /home/aegis/.cache /home/aegis/.streamlit && \
    chown -R aegis:aegis /app /tmp/aegis_fs /home/aegis

WORKDIR /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    HOME=/home/aegis \
    AEGIS_CONFIG_PATH=/app/aegis/config.local_single_qwen.yaml \
    AEGIS_REPORTS_DIR=/app/reports \
    OLLAMA_BASE_URL=http://ollama:11434

USER aegis

# Stage 4 — Runtime: lean CLI scanner image.
FROM runtime-base AS runtime

COPY --from=builder --chown=aegis:aegis /app/.venv /app/.venv
COPY --from=builder --chown=aegis:aegis /app/aegis /app/aegis
COPY --from=builder --chown=aegis:aegis /app/datasets /app/datasets
COPY --from=builder --chown=aegis:aegis /app/schemas /app/schemas

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import aegis; print('ok')"

ENTRYPOINT ["python", "-m", "aegis.cli"]
CMD ["scan"]

# Stage 5 — Dashboard: Streamlit UI with dashboard-only dependencies.
FROM runtime-base AS dashboard

COPY --from=dashboard-builder --chown=aegis:aegis /app/.venv /app/.venv
COPY --from=dashboard-builder --chown=aegis:aegis /app/aegis /app/aegis
COPY --from=dashboard-builder --chown=aegis:aegis /app/datasets /app/datasets
COPY --from=dashboard-builder --chown=aegis:aegis /app/schemas /app/schemas
COPY --from=dashboard-builder --chown=aegis:aegis /app/dashboard /app/dashboard

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')"

ENTRYPOINT ["streamlit", "run", "dashboard/app.py"]
CMD ["--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
