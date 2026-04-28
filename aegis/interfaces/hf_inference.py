"""Hugging Face hosted Inference API client."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from aegis.secret_safety import secret_fingerprint


def api_key_available(config: dict[str, Any]) -> tuple[bool, str]:
    """Return whether the configured API key environment variable is present."""
    token_env = str(config.get("api_key_env") or config.get("hf_token_env") or "PROVIDER_API_KEY")
    token = os.getenv(token_env)
    if token:
        return True, f"API key loaded from {token_env} ({secret_fingerprint(token)})"
    return False, f"missing env {token_env}"


def complete(prompt: str, config: dict[str, Any]) -> str:
    """Call the Hugging Face hosted Inference API."""
    token_env = str(config.get("api_key_env") or config.get("hf_token_env") or "PROVIDER_API_KEY")
    token = os.getenv(token_env)
    if not token:
        raise RuntimeError(f"Hugging Face Inference provider requires env {token_env}")

    model = str(config.get("model") or config.get("hf_model") or "HuggingFaceH4/zephyr-7b-beta")
    timeout_seconds = float(config.get("timeout_seconds", 60))
    max_tokens = int(config.get("max_tokens", 256))
    body = json.dumps({
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": max_tokens,
            "return_full_text": False,
        },
    }).encode("utf-8")

    request = Request(
        f"https://api-inference.huggingface.co/models/{quote(model, safe='')}",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read().decode("utf-8", errors="replace")

    parsed = json.loads(raw)
    text = _extract_text(parsed).strip()
    if not text:
        raise ValueError("Hugging Face Inference response was empty")
    return text


def _extract_text(parsed: object) -> str:
    if isinstance(parsed, list) and parsed:
        first = parsed[0]
        if isinstance(first, dict):
            return str(
                first.get("generated_text")
                or first.get("summary_text")
                or first.get("translation_text")
                or ""
            )
    if isinstance(parsed, dict):
        if "error" in parsed:
            raise ValueError(str(parsed["error"]))
        return str(
            parsed.get("generated_text")
            or parsed.get("summary_text")
            or parsed.get("translation_text")
            or ""
        )
    return ""
