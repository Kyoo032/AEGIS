"""Evaluation sub-package — scoring and detection for attack results."""
from aegis.evaluation.rule_detector import RuleDetector
from aegis.evaluation.scorer import RuleBasedScorer

__all__ = ["RuleBasedScorer", "RuleDetector"]
