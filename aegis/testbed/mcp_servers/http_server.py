"""HTTP request MCP server.

Provides simple GET/POST helpers with conservative defaults.
"""
from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from fastmcp import FastMCP

server = FastMCP("http")

_MAX_RESPONSE_BYTES = 8192
_TIMEOUT_SECONDS = 8
_ALLOWLIST_HOSTS: set[str] = {"localhost", "127.0.0.1", "::1"}
_BLOCK_PRIVATE_NETWORKS = True


def configure_security(config: dict[str, Any]) -> None:
    """Apply HTTP server security policy."""
    global _MAX_RESPONSE_BYTES, _TIMEOUT_SECONDS, _ALLOWLIST_HOSTS, _BLOCK_PRIVATE_NETWORKS

    max_response = config.get("http_max_response_bytes")
    if isinstance(max_response, int) and max_response > 0:
        _MAX_RESPONSE_BYTES = max_response

    timeout_seconds = config.get("http_timeout_seconds")
    if isinstance(timeout_seconds, int | float) and timeout_seconds > 0:
        _TIMEOUT_SECONDS = int(timeout_seconds)

    allowlist = config.get("http_allowlist")
    if isinstance(allowlist, list):
        _ALLOWLIST_HOSTS = {str(host).strip().lower() for host in allowlist if str(host).strip()}

    block_private = config.get("http_block_private_networks")
    if isinstance(block_private, bool):
        _BLOCK_PRIVATE_NETWORKS = block_private


def _validate_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "Invalid URL."

    if parsed.scheme not in {"http", "https"}:
        return False, "Only http/https URLs are allowed."
    if not parsed.netloc:
        return False, "URL must include a host."
    if parsed.username or parsed.password:
        return False, "Credentials in URL are not allowed."
    if any(ord(ch) < 32 for ch in url):
        return False, "URL contains control characters."

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "URL host is empty."

    if host in _ALLOWLIST_HOSTS:
        return True, ""

    if not _BLOCK_PRIVATE_NETWORKS:
        return True, ""

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Non-literal hostnames are blocked under strict mode unless allowlisted.
        return False, f"Host not allowlisted: {host}"

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False, f"Blocked private or special network target: {host}"

    return False, f"Host not allowlisted: {host}"


def _read_body(url: str, *, method: str, body: bytes | None = None) -> str:
    is_valid, reason = _validate_url(url)
    if not is_valid:
        return f"Request blocked: {reason}"

    request = Request(url=url, data=body, method=method)
    try:
        with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            payload = response.read(_MAX_RESPONSE_BYTES)
            return payload.decode("utf-8", errors="replace")
    except HTTPError as exc:
        return f"HTTP error {exc.code}: {exc.reason}"
    except URLError as exc:
        return f"Network error: {exc.reason}"


def fetch_url(url: str) -> str:
    """Fetch a URL with GET and return a truncated response body."""
    return _read_body(url, method="GET")


def post_request(url: str, payload: dict[str, object]) -> str:
    """POST JSON payload and return a truncated response body."""
    body = json.dumps(payload).encode("utf-8")
    return _read_body(url, method="POST", body=body)


TOOLS: dict[str, Callable[..., object]] = {
    "fetch_url": fetch_url,
    "post_request": post_request,
}

server.tool(fetch_url)
server.tool(post_request)


def get_tools() -> dict[str, Callable[..., object]]:
    """Return callable tool map for agent-side local invocation."""
    return dict(TOOLS)
