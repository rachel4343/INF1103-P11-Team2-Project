# rule_engine.py under logic_manager.py
# This module contains the RuleEngine class, which coordinates the evaluation of AI analysis results against all defined priority rules in the PhishGuard system.
# The RuleEngine class runs each rule, collects matching results, and selects the highest-priority result. 
# It provides methods to evaluate all rules and return either all matching results or the single highest-priority result, ensuring that reports are prioritized effectively based on AI analysis and employee actions.


from typing import Dict, List, Optional, Tuple

from .priority_rule import PriorityRule
from .critical_threat_rule import CriticalThreatRule
from .credential_link_rule import CredentialLinkRule
from .high_threat_rule import HighThreatRule
from .medium_threat_rule import MediumThreatRule
from .low_threat_rule import LowThreatRule


# Higher number means higher priority.
PRIORITY_RANK = {
    "Critical": 6,
    "Urgent Security Review": 5,
    "High-Priority Review": 4,
    "Security Review": 3,
    "Low Priority": 1,
}


class RuleEngine:
    """
    Coordinates all priority rules.

    Runs each rule, collects matching results,
    and selects the highest-priority result.
    """

    def __init__(self, rules: Optional[List[PriorityRule]] = None):

        # Use supplied rules, or create the five default rules.
        if rules is not None:
            self._rules = list(rules)
        else:
            self._rules = [
                CriticalThreatRule(),
                CredentialLinkRule(),
                HighThreatRule(),
                MediumThreatRule(),
                LowThreatRule(),
            ]

    def evaluate_all(
        self,
        ai_result: Dict
    ) -> List[Tuple[str, str]]:
        """
        Run every rule and collect all matching results.

        Each rule has its own evaluate() implementation.
        """

        matched = []

        for rule in self._rules:
            result = rule.evaluate(ai_result)

            if result is not None:
                matched.append(result)

        return matched

    def evaluate(
        self,
        ai_result: Dict
    ) -> Optional[Tuple[str, str]]:
        """
        Return the highest-priority matching result.

        Returns None if no rule matches.
        """

        matched = self.evaluate_all(ai_result)

        if not matched:
            return None

        return max(
            matched,
            key=lambda result: PRIORITY_RANK[result[0]]
        )
