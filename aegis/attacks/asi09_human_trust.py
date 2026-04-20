"""ASI09: human trust deception attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class HumanTrustDeceptionModule(BaseAttackModule):
    """Exercise deceptive trust cues in agent output and user guidance."""

    name = "asi09_human_trust"
    owasp_id = "ASI09"
    atlas_technique = None
    description = (
        "Tests deceptive output formatting, fake audit or compliance claims, fake "
        "citations, overconfident safety summaries, and social-engineering guidance "
        "that encourages unsafe user action."
    )
    category = "Human Trust Exploitation"
    default_severity = "high"
