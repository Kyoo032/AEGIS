"""Attack modules sub-package — Person B owns this directory."""
from aegis.attacks.base import BaseAttackModule
from aegis.attacks.llm01_prompt_inject import PromptInjectionModule

__all__ = ["BaseAttackModule", "PromptInjectionModule"]
