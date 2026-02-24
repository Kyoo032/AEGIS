"""Day 6 output filter defense."""
from __future__ import annotations

import json
import re
from typing import Any

from aegis.interfaces.agent import AgentInterface
from aegis.interfaces.defense import Defense

_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_URL_PATTERN = re.compile(r"https?://[^\s)]+", re.IGNORECASE)
_UNIX_PATH_PATTERN = re.compile(
    r"/(?:etc|home|root|var|tmp|usr|opt|srv|proc|dev|mnt|media)(?:/[^\s]+)*",
    re.IGNORECASE,
)
_WINDOWS_PATH_PATTERN = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_PATTERN = re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")

_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("email", _EMAIL_PATTERN, "[REDACTED_EMAIL]"),
    ("url", _URL_PATTERN, "[REDACTED_URL]"),
    ("unix_path", _UNIX_PATH_PATTERN, "[REDACTED_PATH]"),
    ("windows_path", _WINDOWS_PATH_PATTERN, "[REDACTED_PATH]"),
    ("ssn", _SSN_PATTERN, "[REDACTED_SSN]"),
    ("phone", _PHONE_PATTERN, "[REDACTED_PHONE]"),
)


class OutputFilterDefense(Defense):
    """Output defense for PII/exfiltration pattern blocking and redaction."""

    name = "output_filter"
    description = "Blocks or redacts sensitive output patterns (PII/exfiltration/path leaks)."

    def __init__(self, *, block_on_match: bool = True) -> None:
        self._block_on_match = bool(block_on_match)

    def apply(self, agent: AgentInterface) -> None:
        agent.enable_defense(
            self.name,
            {"enabled": True, "block_on_match": self._block_on_match},
        )

    def remove(self, agent: AgentInterface) -> None:
        agent.disable_defense(self.name)

    def inspect(self, input_data: str | dict[str, Any]) -> tuple[bool, str]:
        candidate = self._normalize_input(input_data)
        for label, pattern, _replacement in _PATTERNS:
            if pattern.search(candidate):
                return True, f"sensitive output detected: {label}"
        return False, ""

    def sanitize(self, output_text: str) -> str:
        sanitized = output_text
        for _label, pattern, replacement in _PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    def _normalize_input(self, input_data: str | dict[str, Any]) -> str:
        if isinstance(input_data, dict):
            return json.dumps(input_data, sort_keys=True)
        return str(input_data)
