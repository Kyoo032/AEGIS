"""Day 6 input validator defense."""
from __future__ import annotations

import json
import re
from typing import Any

from aegis.interfaces.agent import AgentInterface
from aegis.interfaces.defense import Defense

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(ignore|override|bypass|forget).{0,40}(system|developer|previous|prior).{0,40}(instruction|prompt|rule)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(reveal|print|show|dump|leak|expose).{0,40}(system prompt|hidden prompt|chain[- ]of[- ]thought|internal policy)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(act as|you are now|system update|new policy).{0,60}(root|admin|developer|operator|maintenance mode)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(?:\$\(|`|;\s*|&&|\|\||/etc/passwd|/etc/shadow|\.\./)",
        re.IGNORECASE,
    ),
)

_ENCODING_KEYWORD_PATTERN = re.compile(r"(decode|base64|hex|rot13|obfuscated|encoded)", re.I)
_BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_BLOB_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{2}){20,}\b")


class InputValidatorDefense(Defense):
    """Input defense enforcing prompt hierarchy and injection guardrails."""

    name = "input_validator"
    description = (
        "Blocks user attempts to override higher-priority instructions and known "
        "injection/encoding patterns."
    )

    def __init__(self, *, strict: bool = False, max_input_chars: int = 8_000) -> None:
        self._strict = bool(strict)
        self._max_input_chars = max(1, int(max_input_chars))

    def apply(self, agent: AgentInterface) -> None:
        """Enable the defense on the target agent."""
        agent.enable_defense(
            self.name,
            {
                "enabled": True,
                "strict": self._strict,
                "max_input_chars": self._max_input_chars,
            },
        )

    def remove(self, agent: AgentInterface) -> None:
        """Disable the defense on the target agent."""
        agent.disable_defense(self.name)

    def inspect(self, input_data: str | dict[str, Any]) -> tuple[bool, str]:
        """Inspect user input and return ``(blocked, reason)``."""
        candidate = self._normalize_input(input_data)
        if not candidate:
            return False, ""

        if len(candidate) > self._max_input_chars:
            return True, "input too long"

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(candidate):
                return True, "injection detected"

        if self._looks_like_encoded_injection(candidate):
            return True, "injection detected"

        if self._strict and self._has_control_characters(candidate):
            return True, "injection detected"

        return False, ""

    def _normalize_input(self, input_data: str | dict[str, Any]) -> str:
        if isinstance(input_data, dict):
            return json.dumps(input_data, sort_keys=True)
        return str(input_data)

    def _looks_like_encoded_injection(self, candidate: str) -> bool:
        has_keyword = bool(_ENCODING_KEYWORD_PATTERN.search(candidate))
        has_blob = bool(_BASE64_BLOB_PATTERN.search(candidate) or _HEX_BLOB_PATTERN.search(candidate))
        if has_keyword and has_blob:
            return True
        if "rot13" in candidate.lower() and "decode" in candidate.lower():
            return True
        return False

    def _has_control_characters(self, candidate: str) -> bool:
        return any(ord(ch) < 9 or (13 < ord(ch) < 32) for ch in candidate)
