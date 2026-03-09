# Stage 1 — Builder: install dependencies and package
FROM python:3.11 AS builder

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --no-dev --frozen

COPY aegis/ aegis/
COPY datasets/ datasets/
COPY schemas/ schemas/
COPY dashboard/ dashboard/

RUN uv pip install --python .venv/bin/python ".[dashboard]"

# Stage 2 — Runtime: CLI scanner
FROM python:3.11-slim AS runtime

RUN groupadd --gid 1000 aegis && \
    useradd --uid 1000 --gid aegis --create-home aegis

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/aegis /app/aegis
COPY --from=builder /app/datasets /app/datasets
COPY --from=builder /app/schemas /app/schemas

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    AEGIS_REPORTS_DIR=/app/reports \
    OLLAMA_BASE_URL=http://ollama:11434

RUN mkdir -p /app/reports && chown aegis:aegis /app/reports

USER aegis

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import aegis; print('ok')"

ENTRYPOINT ["python", "-m", "aegis.cli"]
CMD ["scan"]

# Stage 3 — Dashboard: Streamlit web UI
FROM runtime AS dashboard

USER root
COPY --from=builder /app/dashboard /app/dashboard
RUN chown -R aegis:aegis /app/dashboard
USER aegis

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')"

ENTRYPOINT []
CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
