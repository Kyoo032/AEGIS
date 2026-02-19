"""OWASP LLM Top-10 and ATLAS category descriptions used in AEGIS reports."""
from __future__ import annotations

OWASP_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": (
            "Attacker crafts inputs that override or hijack LLM instructions, "
            "causing the model to perform unintended actions or expose data."
        ),
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "description": (
            "The LLM inadvertently reveals confidential data such as PII, "
            "credentials, or proprietary business information in its outputs."
        ),
    },
    "ASI01": {
        "name": "Agent Goal Hijacking",
        "description": (
            "An attacker redirects the agent's primary objective through direct "
            "or indirect prompt injection, causing it to perform malicious tasks."
        ),
    },
    "ASI02": {
        "name": "Tool Misuse & Exploitation",
        "description": (
            "The agent is manipulated into invoking MCP tools with attacker-supplied "
            "parameters, resulting in unauthorized file access, network calls, or "
            "code execution."
        ),
    },
    "ASI04": {
        "name": "Supply Chain Vulnerabilities",
        "description": (
            "Malicious content is introduced through compromised tools, plugins, "
            "or data sources that the agent trusts, affecting its behavior."
        ),
    },
    "ASI05": {
        "name": "Unexpected Code Execution",
        "description": (
            "The agent is tricked into writing or executing arbitrary code, "
            "which may result in system compromise or data exfiltration."
        ),
    },
    "ASI06": {
        "name": "Memory & Context Poisoning",
        "description": (
            "Attacker injects persistent malicious content into the agent's memory "
            "or RAG store, influencing future responses and tool calls."
        ),
    },
    "MCP06": {
        "name": "Command Injection via MCP",
        "description": (
            "Attacker embeds shell metacharacters or OS commands in MCP tool "
            "parameters, causing the server to execute arbitrary system commands."
        ),
    },
}


def get_owasp_info(owasp_id: str) -> dict[str, str]:
    """Return the name and description for a given OWASP ID.

    Args:
        owasp_id: An OWASP LLM or ASI category identifier e.g. ``"LLM01"``.

    Returns:
        Dict with ``name`` and ``description`` keys.
        Returns an ``"Unknown"`` entry if the ID is not recognised.
    """
    entry = OWASP_DESCRIPTIONS.get(owasp_id)
    if entry is not None:
        return dict(entry)
    return {
        "name": "Unknown",
        "description": f"No description available for OWASP ID '{owasp_id}'.",
    }
