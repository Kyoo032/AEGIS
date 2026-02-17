"""ASI06: Memory & Context Poisoning attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class MemoryPoisonModule(BaseAttackModule):
    """Tests persistence attacks against memory and contextual state."""

    name = "asi06_memory_poison"
    owasp_id = "ASI06"
    atlas_technique = "AML.T0020"
    description = (
        "Tests poisoning of memory and context stores to induce persistent "
        "malicious behavior across turns."
    )
    category = "Memory & Context Poisoning"
    default_severity = "critical"
