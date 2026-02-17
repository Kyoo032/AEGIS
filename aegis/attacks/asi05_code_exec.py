"""ASI05: Unexpected Code Execution attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class CodeExecModule(BaseAttackModule):
    """Tests prompt-to-code paths and arbitrary code execution attempts."""

    name = "asi05_code_exec"
    owasp_id = "ASI05"
    atlas_technique = "AML.T0051"
    description = (
        "Tests resistance to unexpected code execution including shell execution, "
        "sandbox escape attempts, and secret exfiltration via code."
    )
    category = "Unexpected Code Execution"
    default_severity = "critical"
