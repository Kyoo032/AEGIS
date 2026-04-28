"""Streamlit scan launcher for the lightweight hosted demo path."""
from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import streamlit as st
import yaml

from aegis.config import load_config
from aegis.orchestrator import AEGISOrchestrator
from aegis.reporting.report_generator import ReportGenerator
from aegis.secret_safety import parse_secretless_base_url
from dashboard.utils.rate_limit import check_rate_limit
from dashboard.utils.session_reports import get_session_report_dir

_PROVIDER_CHOICES = {
    "Generic chat-completions API": {
        "mode": "openai_compat",
        "api_key_env": "PROVIDER_API_KEY",
        "base_url": "https://api.example.com/v1",
        "model": "replace-with-provider-model",
    },
    "Messages API shape": {
        "mode": "anthropic",
        "api_key_env": "PROVIDER_API_KEY",
        "base_url": "",
        "model": "replace-with-provider-model",
    },
    "Hosted inference API shape": {
        "mode": "hf_inference",
        "api_key_env": "PROVIDER_API_KEY",
        "base_url": "",
        "model": "replace-with-provider-model",
    },
    "Demo offline": {
        "mode": "offline",
        "api_key_env": "",
        "base_url": "",
        "model": "offline-demo",
    },
}
_SCAN_MODULE_CAP = 8
_SCAN_PAYLOAD_CAP = 20
_SCAN_TOTAL_CAP = 120
_ALLOWED_PROVIDER_MODES = frozenset(choice["mode"] for choice in _PROVIDER_CHOICES.values())


def render_run_scan() -> None:
    """Render a BYOK scan form and write reports to a session temp directory."""
    st.header("Run Scan")
    st.caption("Bring your own API key for hosted models, or use the offline demo path for UI validation.")

    defaults = load_config()
    available_modules = [str(item) for item in defaults["attacks"]["modules"]]
    suggested_modules = [
        name
        for name in ("llm01_prompt_inject", "asi02_tool_misuse", "mcp06_cmd_injection")
        if name in available_modules
    ]

    with st.form("aegis_run_scan"):
        provider_name = st.selectbox("Provider", list(_PROVIDER_CHOICES), index=0)
        provider_defaults = _PROVIDER_CHOICES[str(provider_name)]
        model = st.text_input("Model", value=str(provider_defaults["model"]))
        base_url = ""
        if provider_defaults["mode"] == "openai_compat":
            base_url = st.text_input("Base URL", value=str(provider_defaults["base_url"]))
        api_key = ""
        api_key_env = str(provider_defaults["api_key_env"])
        if provider_defaults["mode"] != "offline":
            api_key = st.text_input("API key", type="password")
        modules = st.multiselect(
            "Attack modules",
            available_modules,
            default=suggested_modules,
            max_selections=_SCAN_MODULE_CAP,
        )
        payloads_per_module = st.slider(
            "Payloads per module",
            min_value=1,
            max_value=_SCAN_PAYLOAD_CAP,
            value=5,
            step=1,
        )
        submitted = st.form_submit_button("Run scan", type="primary")

    if submitted is not True:
        return

    if not modules:
        st.error("Select at least one attack module.")
        return

    estimated_payloads = len(modules) * int(payloads_per_module)
    if estimated_payloads > _SCAN_TOTAL_CAP:
        st.error(f"This demo caps each scan at {_SCAN_TOTAL_CAP} payloads.")
        return

    provider_mode = str(_PROVIDER_CHOICES[str(provider_name)]["mode"])
    if provider_mode != "offline" and not api_key.strip():
        st.error("Enter an API key for the selected hosted provider.")
        return

    report_dir = get_session_report_dir()
    try:
        config_payload = _build_scan_config(
            provider_mode=provider_mode,
            api_key_env=api_key_env,
            base_url=base_url,
            model=model,
            modules=[str(name) for name in modules],
            payloads_per_module=int(payloads_per_module),
            output_dir=report_dir,
        )
    except ValueError as exc:
        st.error(str(exc))
        return

    client_id = _session_client_id()
    allowed, retry_after, reason = check_rate_limit(client_id)
    if not allowed:
        st.error(f"{reason}. Try again in about {retry_after // 60 + 1} minute(s).")
        return

    with st.status("Running AEGIS scan", expanded=True) as status:
        st.write(f"Provider adapter: {provider_name}")
        st.write(f"Modules: {len(modules)}")
        st.write(f"Payloads: {estimated_payloads}")
        try:
            report_path = _run_scan(config_payload, api_key_env, api_key, report_dir)
        except Exception as exc:
            status.update(label="Scan failed", state="error")
            st.error(str(exc))
            return
        status.update(label="Scan complete", state="complete")

    st.success(f"Report written to `{report_path}`")
    st.info("Use the report selector in the sidebar to inspect the new scan output.")


def _build_scan_config(
    *,
    provider_mode: str,
    api_key_env: str,
    base_url: str,
    model: str,
    modules: list[str],
    payloads_per_module: int,
    output_dir: Path,
) -> dict[str, Any]:
    provider_mode = _validate_provider_mode(provider_mode)
    model = _validate_model(model, provider_mode)
    modules = _validate_modules(modules)
    payloads_per_module = _validate_payload_count(payloads_per_module)

    provider: dict[str, Any] = {
        "mode": provider_mode,
        "api_key_env": api_key_env,
        "model": model,
        "timeout_seconds": 60,
        "max_tokens": 512,
        "require_external": provider_mode != "offline",
    }
    if provider_mode == "openai_compat":
        provider["base_url"] = _normalize_https_base_url(base_url)
    elif base_url.strip():
        provider["base_url"] = _normalize_https_base_url(base_url)

    return {
        "testbed": {
            "model": model,
            "provider": provider,
            "agent_profile": "default",
        },
        "attacks": {
            "modules": modules,
            "payloads_per_module": payloads_per_module,
            "multi_turn": True,
        },
        "evaluation": {"scorers": ["rule_based"]},
        "defenses": {},
        "reporting": {
            "output_dir": str(output_dir),
            "formats": ["json"],
            "include_atlas_mapping": True,
        },
    }


def _validate_provider_mode(provider_mode: str) -> str:
    normalized = str(provider_mode).strip()
    if normalized not in _ALLOWED_PROVIDER_MODES:
        raise ValueError(f"Unsupported provider mode: {normalized}")
    return normalized


def _validate_model(model: str, provider_mode: str) -> str:
    normalized = str(model).strip()
    if not normalized:
        raise ValueError("Model is required.")
    if provider_mode != "offline" and normalized == "replace-with-provider-model":
        raise ValueError("Set a concrete hosted model before running a scan.")
    return normalized


def _validate_modules(modules: list[str]) -> list[str]:
    normalized = [str(name).strip() for name in modules if str(name).strip()]
    if not normalized:
        raise ValueError("Select at least one attack module.")
    if len(normalized) > _SCAN_MODULE_CAP:
        raise ValueError(f"This demo caps each scan at {_SCAN_MODULE_CAP} modules.")
    return normalized


def _validate_payload_count(payloads_per_module: int) -> int:
    count = int(payloads_per_module)
    if count < 1 or count > _SCAN_PAYLOAD_CAP:
        raise ValueError(f"Payloads per module must be between 1 and {_SCAN_PAYLOAD_CAP}.")
    return count


def _normalize_https_base_url(base_url: str) -> str:
    parsed = parse_secretless_base_url(
        base_url,
        allowed_schemes=frozenset({"https"}),
        label="Hosted demo",
    )
    return parsed.geturl().rstrip("/")


def _run_scan(
    config_payload: dict[str, Any],
    api_key_env: str,
    api_key: str,
    report_dir: Path,
) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
        yaml.safe_dump(config_payload, fh, sort_keys=False)
        config_path = Path(fh.name)

    try:
        with _temporary_api_key(api_key_env, api_key):
            orchestrator = AEGISOrchestrator(config_path=str(config_path))
            report = orchestrator.run_baseline()
        rendered = ReportGenerator().render_json(report)
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        report_path = report_dir / f"aegis_scan_{timestamp}_{uuid4().hex[:8]}.json"
        report_path.write_text(rendered, encoding="utf-8")
        return report_path
    finally:
        config_path.unlink(missing_ok=True)


@contextmanager
def _temporary_api_key(api_key_env: str, api_key: str):
    if not api_key_env:
        yield
        return

    original = os.environ.get(api_key_env)
    if api_key:
        os.environ[api_key_env] = api_key
    try:
        yield
    finally:
        if original is None:
            os.environ.pop(api_key_env, None)
        else:
            os.environ[api_key_env] = original


def _session_client_id() -> str:
    existing = st.session_state.get("aegis_demo_client_id")
    if existing:
        return str(existing)
    client_id = uuid4().hex
    st.session_state["aegis_demo_client_id"] = client_id
    return client_id
