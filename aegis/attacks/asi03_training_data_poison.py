"""ASI03: Training Data Poisoning attack module stub."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class TrainingDataPoisonModule(BaseAttackModule):
    """Placeholder stub for ASI03 attack track."""

    name = "asi03_training_data_poison"
    owasp_id = "ASI03"
    atlas_technique = None
    description = (
        "Stub module for testing poisoning risks introduced through compromised "
        "training or tuning data artifacts."
    )
    category = "Training Data Poisoning"
    default_severity = "high"
