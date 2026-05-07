"""Docker compose smoke test — secret-leak check on a real ollama scan.

Gated behind RUN_DOCKER_TESTS=1 and requires docker + ollama with
qwen3.5:0.8b already pulled. Run with:

    RUN_DOCKER_TESTS=1 pytest tests/test_docker_smoke.py -s -v
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

_SECRET_PATTERN = re.compile(
    r"sk-[A-Za-z0-9]{20,}|sk-ant-api[A-Za-z0-9\-]{20,}|hf_[A-Za-z0-9]{20,}"
)
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _model_present(model_name: str = "qwen") -> bool:
    result = subprocess.run(
        ["docker", "compose", "--profile", "local", "exec", "-T", "ollama", "ollama", "list"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and model_name in result.stdout


@pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1",
    reason="Set RUN_DOCKER_TESTS=1 to enable Docker smoke tests",
)
@pytest.mark.skipif(not _docker_available(), reason="docker not on PATH")
def test_docker_ollama_scan_reports_no_secrets() -> None:
    """Runs a real ollama scan inside Docker and asserts reports contain no secrets."""
    if not _model_present():
        pytest.skip(
            "qwen3.5:0.8b not found in ollama container — "
            "run: docker compose --profile local up -d ollama && "
            "docker compose --profile local run --rm ollama-init"
        )

    with tempfile.TemporaryDirectory() as tmp_reports:
        result = subprocess.run(
            [
                "docker", "compose", "run", "--rm",
                "-e", "AEGIS_PROVIDER_MODE=ollama",
                "-v", f"{tmp_reports}:/app/reports",
                "aegis", "scan", "--format", "json", "--output", "/app/reports",
            ],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, (
            f"Scan exited {result.returncode}:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        report_files = list(Path(tmp_reports).rglob("*.json"))
        assert report_files, "No JSON report generated — scan may have failed silently"

        for report_path in report_files:
            content = report_path.read_text(encoding="utf-8")
            match = _SECRET_PATTERN.search(content)
            assert match is None, (
                f"Secret pattern '{match.group()}' found in {report_path.name}"
            )
