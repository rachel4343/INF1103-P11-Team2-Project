# logic_manager.py
# This module contains the LogicManager class, which coordinates the AI analysis, business rules, risk scoring, and review management for phishing reports.
# Uses the RuleEngine, RiskScorer, and ActionEscalator classes to apply business logic and determine report priorities.
# Uses priority rules defined in priority_rule.py to evaluate AI results and determine the appropriate priority level for each report.

# Overall structure:
# 1. Constants: Defines threat levels, review statuses, priorities, and other constants used throughout the logic manager.
# 2. Constructor: Initializes the LogicManager with instances of RuleEngine, RiskScorer, and ActionEscalator.
# 3. AI Result Validation: Methods to check if the AI result is usable and to count warning indicators.
# 4. Business Rule Coordination: Applies business rules to determine the priority of a report based on the AI result and employee actions.
# 5. Risk Scoring Delegation: Delegates risk scoring to the RiskScorer class and provides methods to get the risk score and breakdown.
# 6. Report ID Generation: Generates the next report ID based on existing records.
# 7. Final Report Creation: Builds the final report record with all relevant information, including AI analysis, priority, and review status.
# 8. Review Management: Applies updates to the report based on reviewer actions, including first and second reviews, priority overrides, and notes.
# 9. Lookup and Sorting: Methods to find a report by ID and sort records by priority, risk score, and report ID.
# 10. Password Verification: Methods to hash and verify the IT password for secure access to the system.


import copy
import hashlib
import hmac
import os
import re

from typing import Dict, List, Optional, Tuple

from .rule_engine import RuleEngine
from .risk_scorer import RiskScorer
from .action_escalator import ActionEscalator
from .priority_rule import INDICATOR_FIELDS as SHARED_INDICATOR_FIELDS

class LogicManager:

    # ==========================================
    # 1. CONSTANTS
    # ==========================================

    THREAT_LEVELS = ("low", "medium", "high", "critical")

    REVIEW_STATUSES = (
        "Pending Review",
        "Under Investigation",
        "Resolved",
        "False Positive",
        "Done"
    )

    PRIORITIES = (
        "Critical",
        "Urgent Security Review",
        "High-Priority Review",
        "Security Review",
        "Low Priority",
        "Manual Review Required"
    )

    PRIORITY_RANK = {
        "Critical": 6,
        "Urgent Security Review": 5,
        "High-Priority Review": 4,
        "Security Review": 3,
        "Manual Review Required": 2,
        "Low Priority": 1
    }

    INDICATOR_FIELDS = SHARED_INDICATOR_FIELDS

    RULE_INPUT_FIELDS = ("threat_level", "confidence") + INDICATOR_FIELDS

    MAX_NOTE_LENGTH = 1000
    MAX_REVIEWER_LENGTH = 60
    MAX_REJECTION_REASON_LENGTH = 5000

    IT_PASSWORD_SALT = "phishguard-it-salt"
    IT_PASSWORD_ITERATIONS = 200_000
    IT_PASSWORD_HASH = (
        "ccc2851ae88e1b4f09e719824fb3d1bd"
        "3f6e27e63ba9e213bf628d8aef1d0519"
    )

    # ==========================================
    # 2. CONSTRUCTOR
    # ==========================================

    def __init__(self):

        self.rule_engine = RuleEngine()
        self.risk_scorer = RiskScorer()
        self.action_escalator = ActionEscalator()

    # ==========================================
    # 3. AI RESULT VALIDATION
    # ==========================================

    def has_usable_ai_result(self, ai_result):

        if not isinstance(ai_result, dict):
            return False

        if any(
            ai_result.get(field) is None
            for field in self.RULE_INPUT_FIELDS
        ):
            return False

        confidence = ai_result["confidence"]

        return (
            ai_result["threat_level"] in self.THREAT_LEVELS
            and isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and 0.0 <= confidence <= 1.0
        )

    @staticmethod
    def count_indicators(ai_result):
        """Count the number of warning indicators that are True."""

        return sum(
            1
            for field in LogicManager.INDICATOR_FIELDS
            if ai_result.get(field)
        )

    def has_conflicting_indicators(self, ai_result):

        return (
            ai_result["threat_level"] == "low"
            and self.count_indicators(ai_result) > 0
        )

    # ==========================================
    # 4. BUSINESS RULE COORDINATION
    # ==========================================

    def apply_business_rules(self, report, ai_result):

        if not self.has_usable_ai_result(ai_result):

            priority = "Manual Review Required"

            triggered = [
                "Manual Review Required, because the AI result "
                "was unavailable or incomplete"
            ]

            ai = {}

        else:

            ai = ai_result

            matched = self.rule_engine.evaluate(ai)

            if matched is not None:
                priority, reason = matched
                triggered = [reason]

            elif ai["threat_level"] in ("high", "critical"):

                priority = "Security Review"

                triggered = [
                    f"Security Review, because the AI rated "
                    f"the threat {ai['threat_level']} but was not "
                    "sure enough for a firm rule"
                ]

            else:

                priority = "Manual Review Required"

                triggered = [
                    "Manual Review Required, because the AI "
                    "was not sure enough to decide"
                ]

            if (
                self.has_conflicting_indicators(ai)
                and self.PRIORITY_RANK[priority]
                < self.PRIORITY_RANK["Security Review"]
            ):

                priority = "Security Review"

                triggered.append(
                    "Upgraded to Security Review because the AI "
                    "rated it low but still found warning signs"
                )

        # Delegate employee-action escalation.
        priority = self.action_escalator.escalate(
            report,
            ai,
            priority,
            triggered
        )

        return {
            "priority": priority,
            "rules_triggered": triggered
        }

    # ==========================================
    # 5. RISK SCORING DELEGATION
    # ==========================================

    def risk_score(self, ai_result):

        return self.risk_scorer.calculate_score(ai_result)

    def risk_breakdown(self, ai_result):

        breakdown = self.risk_scorer.get_breakdown(ai_result)

        # Preserve the original Phase 1 string format.
        level = breakdown["threat_level"]
        parts = [f"{level} threat {breakdown['threat_points']}"]

        for indicator, details in breakdown["indicators"].items():

            labels = {
                "impersonation": "impersonation",
                "urgency_manipulation": "urgency pressure",
                "credential_request": "credential request",
                "suspicious_link": "suspicious link",
                "attachment_risk": "risky attachment"
            }

            parts.append(f"{details['label']} {details['points']}")

        return " + ".join(parts) + f" = {breakdown['total_score']}"

   