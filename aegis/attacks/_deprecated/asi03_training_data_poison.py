"""Deprecated ASI03 training-data-poisoning scaffold.

AEGIS v2 renames ASI03 coverage to identity and privilege abuse.
"""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class TrainingDataPoisonModule(BaseAttackModule):
    """Deprecated placeholder for the old ASI03 attack track."""

    name = "asi03_training_data_poison"
    owasp_id = "ASI03"
    atlas_technique = None
    description = (
        "Deprecated ASI03 scaffold for training or tuning data poisoning. "
        "Use asi03_identity_privilege for AEGIS v2."
    )
    category = "Training Data Poisoning"
    default_severity = "high"
