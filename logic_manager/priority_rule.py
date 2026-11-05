# priority_rule.py under logic_manager.py
# This module contains the PriorityRule abstract base class, which defines the interface for all priority rules in the PhishGuard system.
# The PriorityRule class provides methods for evaluating AI analysis results against specific criteria, counting warning indicators, and checking confidence thresholds. 
# Each child rule must implement the evaluate() method to determine if it matches the AI result and return the appropriate priority and explanation.


from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

INDICATOR_FIELDS = (
    "impersonation",
    "urgency_manipulation",
    "credential_request",
    "suspicious_link",
    "attachment_risk",
)

class PriorityRule(ABC):
    """
    Abstract parent class for all PhishGuard priority rules.

    Every child rule must implement evaluate().
    """

    @abstractmethod
    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:
        """
        Check whether this rule matches the AI result.

        Returns:
            (priority, explanation) if the rule matches.
            None if the rule does not match.
        """
        pass

    @staticmethod
    def count_indicators(ai_result):
        """Count the number of warning indicators that are True."""

        return sum(
            1
            for field in INDICATOR_FIELDS
            if ai_result.get(field)
        )

    @staticmethod
    def confidence_gate(
        ai_result: Dict,
        normal_threshold: float,
        corroborated_threshold: float
    ) -> str:
        """
        Check whether the AI confidence is sufficient.

        Three or more warning indicators allow the lower
        corroborated confidence threshold.
        """

        confidence = ai_result["confidence"]

        if confidence >= normal_threshold:
            return f"{confidence:.0%} sure"

        indicators = PriorityRule.count_indicators(ai_result)

        if indicators >= 3 and confidence >= corroborated_threshold:
            return (
                f"{confidence:.0%} sure, "
                f"backed by {indicators} warning signs"
            )

        return ""
