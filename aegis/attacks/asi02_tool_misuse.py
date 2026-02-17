"""ASI02: Tool Misuse & Exploitation attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class ToolMisuseModule(BaseAttackModule):
    """Tests unsafe and unauthorized usage of legitimate tools."""

    name = "asi02_tool_misuse"
    owasp_id = "ASI02"
    atlas_technique = "AML.T0040"
    description = (
        "Tests misuse of MCP tools via parameter injection, unsafe tool chaining, "
        "scope escalation, and destructive operations."
    )
    category = "Tool Misuse & Exploitation"
    default_severity = "high"
