"""LLM01 extension: cross-lingual prompt injection attack module."""
from __future__ import annotations

from aegis.attacks.base import BaseAttackModule


class CrossLingualPromptInjectionModule(BaseAttackModule):
    """Exercise multilingual, code-switched, and obfuscated prompt injection."""

    name = "llm01_crosslingual"
    owasp_id = "LLM01"
    atlas_technique = "AML.T0051"
    description = (
        "Tests cross-lingual prompt injection using Indonesian, code-switching, "
        "Malay/Indonesian similarity, transliteration, mixed scripts, homoglyphs, "
        "and multilingual role instructions."
    )
    category = "Cross-Lingual Prompt Injection"
    default_severity = "high"

