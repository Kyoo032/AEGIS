"""ASI01: Agent Goal Hijacking attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class GoalHijackModule(BaseAttackModule):
    """Tests goal redirection and priority hijack behavior."""

    name = "asi01_goal_hijack"
    owasp_id = "ASI01"
    atlas_technique = "AML.T0051"
    description = (
        "Tests agent resistance to goal hijacking through direct overrides, "
        "indirect injection, persona switching, and priority manipulation."
    )
    category = "Agent Goal Hijacking"
    default_severity = "critical"
