"""MITRE ATLAS technique descriptions used in AEGIS reports."""
from __future__ import annotations

ATLAS_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "AML.T0051": {
        "name": "LLM Prompt Injection",
        "description": (
            "An adversary crafts inputs that alter the LLM's behaviour by "
            "overriding or hijacking its instructions, goals, or context."
        ),
    },
    "AML.T0040": {
        "name": "Craft Adversarial Data",
        "description": (
            "An adversary creates specially crafted inputs designed to cause "
            "a machine learning model to produce incorrect or harmful outputs."
        ),
    },
    "AML.T0010": {
        "name": "ML Supply Chain Compromise",
        "description": (
            "An adversary compromises components of the ML pipeline—such as "
            "libraries, pre-trained models, or data sources—to inject malicious "
            "behaviour into the target system."
        ),
    },
    "AML.T0020": {
        "name": "Poison Training Data",
        "description": (
            "An adversary introduces malicious examples into the training dataset "
            "to cause the model to learn incorrect associations or backdoors."
        ),
    },
    "AML.T0024": {
        "name": "Exfiltration via ML Inference API",
        "description": (
            "An adversary exploits the model's inference API to extract sensitive "
            "information by analysing the model's outputs over multiple queries."
        ),
    },
}


def get_atlas_info(technique_id: str) -> dict[str, str]:
    """Return the name and description for a given ATLAS technique ID.

    Args:
        technique_id: A MITRE ATLAS technique identifier e.g. ``"AML.T0051"``.

    Returns:
        Dict with ``name`` and ``description`` keys.
        Returns an ``"Unknown"`` entry if the ID is not recognised.
    """
    entry = ATLAS_DESCRIPTIONS.get(technique_id)
    if entry is not None:
        return dict(entry)
    return {
        "name": "Unknown",
        "description": f"No description available for ATLAS technique '{technique_id}'.",
    }
