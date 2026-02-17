"""ASI04: Supply Chain Vulnerabilities attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class SupplyChainModule(BaseAttackModule):
    """Tests poisoned components such as tools and RAG documents."""

    name = "asi04_supply_chain"
    owasp_id = "ASI04"
    atlas_technique = "AML.T0010"
    description = (
        "Tests susceptibility to poisoned tool descriptions, rug-pull behavior, "
        "and compromised runtime dependencies."
    )
    category = "Supply Chain Vulnerabilities"
    default_severity = "critical"
