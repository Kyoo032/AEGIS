"""Anthropic Messages API client."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.request import Request, urlopen

from aegis.secret_safety import secret_fingerprint


def api_key_available(config: dict[str, Any]) -> tuple[bool, str]:
    """Return whether the configured API key environment variable is present."""
    token_env = str(config.get("api_key_env", "PROVIDER_API_KEY"))
    token = os.getenv(token_env)
    if token:
        return True, f"API key loaded from {token_env} ({secret_fingerprint(token)})"
    return False, f"missing env {token_env}"


def complete(prompt: str, config: dict[str, Any]) -> str:
    """Call Anthropic's Messages API."""
    token_env = str(config.get("api_key_env", "PROVIDER_API_KEY"))
    token = os.getenv(token_env)
    if not token:
        raise RuntimeError(f"Anthropic provider requires env {token_env}")

    model = str(config.get("model") or config.get("provider_model") or "claude-3-5-haiku-latest")
    timeout_seconds = float(config.get("timeout_seconds", 60))
    max_tokens = int(config.get("max_tokens", 512))
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    request = Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        method="POST",
        headers={
            "x-api-key": token,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read().decode("utf-8", errors="replace")

    parsed = json.loads(raw)
    content = parsed.get("content")
    if not isinstance(content, list) or not content:
        raise ValueError("Anthropic response did not include content")
    parts = [
        str(item.get("text", "")).strip()
        for item in content
        if isinstance(item, dict) and item.get("type") == "text"
    ]
    text = "\n".join(part for part in parts if part).strip()
    if not text:
        raise ValueError("Anthropic response was empty")
    return text
