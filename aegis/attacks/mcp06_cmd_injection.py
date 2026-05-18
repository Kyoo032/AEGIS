"""MCP06: Command Injection via MCP attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class CmdInjectionModule(BaseAttackModule):
    """Tests command injection patterns through tool parameters."""

    name = "mcp06_cmd_injection"
    owasp_id = "MCP06"
    atlas_technique = "AML.T0040"
    description = (
        "Tests command injection against MCP-integrated tools via shell metacharacters, "
        "path traversal, SQL-style abuse, and MCP server spoofing through tool-name "
        "collision, manifest manipulation, DNS redirect, and capability upgrade injection."
    )
    category = "Command Injection via MCP"
    default_severity = "critical"
