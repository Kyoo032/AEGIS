"""Local HTTP fixture that serves differential scanner/agent content."""
from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import yaml


@dataclass(frozen=True)
class CloakedHTTPRule:
    """Differential response rule for one path."""

    path: str = "/"
    scanner_body: str = "benign scanner content"
    agent_body: str = "malicious agent trap"
    agent_user_agents: list[str] = field(default_factory=lambda: ["aegis-agent"])
    agent_headers: dict[str, str] = field(default_factory=dict)
    agent_query_params: dict[str, str] = field(default_factory=dict)
    agent_fingerprints: list[str] = field(default_factory=list)
    agent_after_seconds: float | None = None


@dataclass(frozen=True)
class CloakedHTTPServer:
    """Running cloaked HTTP server handle."""

    base_url: str
    server: ThreadingHTTPServer
    thread: threading.Thread


class CloakedHTTPFixture:
    """Serve benign content to scanners and trap content to agent-like clients."""

    def __init__(self, rules: list[CloakedHTTPRule] | None = None) -> None:
        self.rules = rules or [CloakedHTTPRule()]

    @classmethod
    def from_yaml(cls, path: str) -> CloakedHTTPFixture:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        rules = [CloakedHTTPRule(**item) for item in raw.get("rules", [])]
        return cls(rules=rules)

    @contextmanager
    def run(self, host: str = "127.0.0.1", port: int = 0) -> Iterator[CloakedHTTPServer]:
        rules_by_path = {rule.path: rule for rule in self.rules}
        started_at = time.monotonic()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                rule = rules_by_path.get(parsed.path) or rules_by_path.get("/")
                if rule is None:
                    self.send_response(404)
                    self.end_headers()
                    return

                body = (
                    rule.agent_body
                    if _is_agent_request(self, parsed.query, rule, started_at)
                    else rule.scanner_body
                )
                encoded = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = ThreadingHTTPServer((host, port), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        running = CloakedHTTPServer(
            base_url=f"http://{host}:{server.server_port}",
            server=server,
            thread=thread,
        )
        try:
            yield running
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def _is_agent_request(
    handler: BaseHTTPRequestHandler,
    query: str,
    rule: CloakedHTTPRule,
    started_at: float,
) -> bool:
    user_agent = handler.headers.get("User-Agent", "").lower()
    user_agent_match = any(token.lower() in user_agent for token in rule.agent_user_agents)
    header_match = bool(rule.agent_headers) and all(
        handler.headers.get(key) == value for key, value in rule.agent_headers.items()
    )
    params = parse_qs(query)
    query_match = bool(rule.agent_query_params) and all(
        params.get(key, [None])[-1] == value for key, value in rule.agent_query_params.items()
    )
    fingerprint = handler.headers.get("X-AEGIS-Fingerprint") or params.get("fingerprint", [None])[-1]
    fingerprint_match = bool(fingerprint) and fingerprint in rule.agent_fingerprints
    timing_match = (
        rule.agent_after_seconds is not None
        and time.monotonic() - started_at >= rule.agent_after_seconds
    )
    return user_agent_match or header_match or query_match or fingerprint_match or timing_match
