"""ASI10: rogue agent attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class RogueAgentModule(BaseAttackModule):
    """Exercise unauthorized, unmonitored, or out-of-scope agent behaviors."""

    name = "asi10_rogue_agent"
    owasp_id = "ASI10"
    atlas_technique = None
    description = (
        "Tests rogue agent behaviors: unauthorized agent registration, shadow "
        "persistence after revocation, autonomous goal expansion / scope creep, "
        "unsanctioned child-agent spawning, off-policy actions outside the "
        "declared capability manifest, and unsanctioned outbound beaconing."
    )
    category = "Rogue Agents"
    default_severity = "high"
