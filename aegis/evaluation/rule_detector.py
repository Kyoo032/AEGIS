"""Pattern detection rules for evaluating attack results.

Provides detection functions and a ``RuleDetector`` orchestrator.
Each rule inspects an ``AttackResult`` and returns a ``RuleMatch``
indicating whether suspicious behavior was detected.

Detection functions are implemented in sub-modules under ``aegis.evaluation.rules``.
This module re-exports the complete public surface and assembles the rule registry.
"""
from __future__ import annotations

from collections.abc import Callable

from aegis.evaluation.rules._helpers import (
    RuleMatch,
    _is_negative_control,
    _is_refusal,
)
from aegis.evaluation.rules.compliance import detect_instruction_compliance
from aegis.evaluation.rules.exfiltration import (
    detect_data_exfiltration_email,
    detect_data_exfiltration_url,
    detect_sensitive_data_in_email,
    detect_sensitive_file_access,
)
from aegis.evaluation.rules.injection import (
    detect_command_injection,
    detect_injected_instruction_echo,
    detect_parameter_injection,
    detect_tool_output_injection,
    detect_trap_content,
)
from aegis.evaluation.rules.retrieval import (
    detect_poisoned_retrieval,
    detect_supply_chain_indicators,
    detect_untrusted_retrieval_dominance,
)
from aegis.evaluation.rules.social import (
    detect_crosslingual_instruction_followed,
    detect_hitl_approval_mismatch,
    detect_human_trust_deception,
    detect_persona_adoption,
    detect_unverified_peer_instruction,
)
from aegis.evaluation.rules.tool_abuse import (
    detect_restricted_tool_call,
    detect_suspicious_tool_params,
    detect_token_or_authority_abuse,
    detect_tool_chaining,
)
from aegis.models import AttackResult

__all__ = [
    "RuleDetector",
    "RuleMatch",
    "detect_command_injection",
    "detect_crosslingual_instruction_followed",
    "detect_data_exfiltration_email",
    "detect_hitl_approval_mismatch",
    "detect_data_exfiltration_url",
    "detect_injected_instruction_echo",
    "detect_instruction_compliance",
    "detect_parameter_injection",
    "detect_persona_adoption",
    "detect_poisoned_retrieval",
    "detect_restricted_tool_call",
    "detect_token_or_authority_abuse",
    "detect_trap_content",
    "detect_human_trust_deception",
    "detect_unverified_peer_instruction",
    "detect_sensitive_data_in_email",
    "detect_sensitive_file_access",
    "detect_supply_chain_indicators",
    "detect_suspicious_tool_params",
    "detect_tool_chaining",
    "detect_tool_output_injection",
    "detect_untrusted_retrieval_dominance",
]

_ALL_RULES: dict[str, Callable[[AttackResult], RuleMatch]] = {
    "detect_instruction_compliance": detect_instruction_compliance,
    "detect_suspicious_tool_params": detect_suspicious_tool_params,
    "detect_data_exfiltration_email": detect_data_exfiltration_email,
    "detect_data_exfiltration_url": detect_data_exfiltration_url,
    "detect_sensitive_file_access": detect_sensitive_file_access,
    "detect_command_injection": detect_command_injection,
    "detect_injected_instruction_echo": detect_injected_instruction_echo,
    "detect_persona_adoption": detect_persona_adoption,
    "detect_tool_chaining": detect_tool_chaining,
    "detect_parameter_injection": detect_parameter_injection,
    "detect_supply_chain_indicators": detect_supply_chain_indicators,
    "detect_sensitive_data_in_email": detect_sensitive_data_in_email,
    "detect_tool_output_injection": detect_tool_output_injection,
    "detect_trap_content": detect_trap_content,
    "detect_token_or_authority_abuse": detect_token_or_authority_abuse,
    "detect_restricted_tool_call": detect_restricted_tool_call,
    "detect_crosslingual_instruction_followed": detect_crosslingual_instruction_followed,
    "detect_unverified_peer_instruction": detect_unverified_peer_instruction,
    "detect_hitl_approval_mismatch": detect_hitl_approval_mismatch,
    "detect_human_trust_deception": detect_human_trust_deception,
    "detect_poisoned_retrieval": detect_poisoned_retrieval,
    "detect_untrusted_retrieval_dominance": detect_untrusted_retrieval_dominance,
}


class RuleDetector:
    """Orchestrates all detection rules against an AttackResult."""

    def run_all(self, result: AttackResult) -> list[RuleMatch]:
        """Run all configured detection rules and return results."""
        if _is_negative_control(result):
            return [RuleMatch(False, "") for _ in _ALL_RULES.values()]
        if _is_refusal(result.response.final_output) and not result.response.tool_calls:
            return [RuleMatch(False, "") for _ in _ALL_RULES.values()]
        return [rule_fn(result) for rule_fn in _ALL_RULES.values()]

    def run_named(self, name: str, result: AttackResult) -> RuleMatch:
        """Run a single named rule.

        Raises:
            ValueError: If the rule name is not recognized.
        """
        rule_fn = _ALL_RULES.get(name)
        if rule_fn is None:
            msg = (
                f"Unknown rule: '{name}'. "
                f"Available rules: {sorted(_ALL_RULES.keys())}"
            )
            raise ValueError(msg)
        return rule_fn(result)
