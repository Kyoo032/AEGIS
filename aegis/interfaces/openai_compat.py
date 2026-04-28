"""Hosted chat-completion client for OpenAI-compatible API shapes."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.request import Request, urlopen

from aegis.secret_safety import parse_secretless_base_url, secret_fingerprint


def api_key_available(config: dict[str, Any]) -> tuple[bool, str]:
    """Return whether the configured API key environment variable is present."""
    token_env = str(config.get("api_key_env", "PROVIDER_API_KEY"))
    token = os.getenv(token_env)
    if token:
        return True, f"API key loaded from {token_env} ({secret_fingerprint(token)})"
    return False, f"missing env {token_env}"


def complete(prompt: str, config: dict[str, Any]) -> str:
    """Call an OpenAI-compatible chat completions endpoint."""
    token_env = str(config.get("api_key_env", "PROVIDER_API_KEY"))
    token = os.getenv(token_env)
    if not token:
        raise RuntimeError(f"OpenAI-compatible provider requires env {token_env}")

    base_url = _validated_base_url(str(config.get("base_url", "https://api.openai.com/v1")))
    model = str(config.get("model") or config.get("provider_model") or "gpt-4o-mini")
    timeout_seconds = float(config.get("timeout_seconds", 60))
    max_tokens = int(config.get("max_tokens", 512))
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": max_tokens,
    }).encode("utf-8")

    request = Request(
        f"{base_url}/chat/completions",
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
    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("OpenAI-compatible response did not include choices")
    message = choices[0].get("message", {})
    content = message.get("content", "")
    text = str(content).strip()
    if not text:
        raise ValueError("OpenAI-compatible response was empty")
    return text


def _validated_base_url(base_url: str) -> str:
    parsed = parse_secretless_base_url(
        base_url,
        allowed_schemes=frozenset({"http", "https"}),
        label="OpenAI-compatible",
    )
    return parsed.geturl().rstrip("/")
