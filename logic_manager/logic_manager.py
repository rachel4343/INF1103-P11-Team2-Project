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
# 10. Password Verification: Methods to hash and verify the IT password for secure access to the systems.


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

    # ==========================================
    # 6. REPORT ID GENERATION
    # ==========================================

    @staticmethod
    def next_report_id(records):

        highest = 0

        for record in records or []:

            rid = (
                record.get("report_id", "")
                if isinstance(record, dict)
                else ""
            )

            match = re.fullmatch(r"PG-(\d+)", str(rid))

            if match:
                highest = max(highest, int(match.group(1)))

        return f"PG-{highest + 1:04d}"

    # ==========================================
    # 7. FINAL REPORT CREATION
    # ==========================================

    def build_final_record(
        self,
        report_id,
        report,
        ai_result,
        ai_error=None
    ):

        valid = self.has_usable_ai_result(ai_result)

        decision = self.apply_business_rules(report, ai_result)

        return {
            "report_id": report_id,
            "report": report,
            "ai_analysis": ai_result if valid else None,
            "ai_error": "" if valid else (
                ai_error or "AI result unavailable"
            ),
            "threat_level": (
                ai_result["threat_level"] if valid else "unknown"
            ),
            "attack_type": (
                (ai_result.get("attack_type") or "unknown")
                if valid else "unknown"
            ),
            "indicator_count": (
                self.count_indicators(ai_result) if valid else 0
            ),
            "risk_score": (
                self.risk_score(ai_result) if valid else 0
            ),
            "risk_breakdown": (
                self.risk_breakdown(ai_result)
                if valid else "not available (no AI result)"
            ),
            "system_priority": decision["priority"],
            "priority": decision["priority"],
            "priority_overridden": False,
            "rules_triggered": decision["rules_triggered"],
            "review_status": "Pending Review",
            "review_stage": "first_review",
            "first_reviewed_by": "",
            "report_outcome": "",
            "risk_level": "",
            "final_review_decision": "",
            "assigned_reviewer": "",
            "review_history": [],
            "investigation_notes": []
        }

    # ==========================================
    # 8. REVIEW MANAGEMENT
    # ==========================================

    def apply_review_update(self, record, updates):

        errors = []

        action = updates.get("review_action")
        status = updates.get("review_status")
        override = updates.get("priority_override")

        note = str(updates.get("note") or "").strip()
        reviewer = str(
            updates.get("assigned_reviewer") or ""
        ).strip()

        rejection_reason = str(
            updates.get("rejection_reason") or ""
        ).strip()

        if action not in (None, "first", "second"):
            errors.append("Invalid review action.")

        if status is not None and status not in self.REVIEW_STATUSES:
            errors.append(f"Invalid review status: {status}")

        if override is not None and override not in self.PRIORITIES:
            errors.append(f"Invalid priority: {override}")

        if len(note) > self.MAX_NOTE_LENGTH:
            errors.append(
                f"Note is too long (max {self.MAX_NOTE_LENGTH} characters)"
            )

        if len(reviewer) > self.MAX_REVIEWER_LENGTH:
            errors.append(
                f"Reviewer name is too long "
                f"(max {self.MAX_REVIEWER_LENGTH} characters)"
            )

        if len(rejection_reason) > self.MAX_REJECTION_REASON_LENGTH:
            errors.append(
                f"Rejection reason is too long "
                f"(max {self.MAX_REJECTION_REASON_LENGTH} characters)"
            )

        if action == "first":

            first_reviewer = str(
                updates.get("reviewer") or ""
            ).strip()

            outcome = updates.get("report_outcome")
            risk_level = updates.get("risk_level")

            if (
                not first_reviewer
                or len(first_reviewer) > self.MAX_REVIEWER_LENGTH
            ):
                errors.append(
                    "Enter a reviewer name (max 60 characters)."
                )

            if not reviewer:
                errors.append(
                    "Assign the report to the next reviewer."
                )

            if outcome not in (
                "Resolved (real scam)",
                "False Positive (not a scam)"
            ):
                errors.append(
                    "Choose Resolved or False Positive as the investigation outcome."
                )

            if risk_level not in ("Low", "High"):
                errors.append("Choose Low or High as the risk level.")

            if (
                first_reviewer
                and reviewer
                and first_reviewer.casefold() == reviewer.casefold()
            ):
                errors.append(
                    "The next reviewer must be a different person."
                )

        elif action == "second":

            second_reviewer = str(
                updates.get("reviewer") or ""
            ).strip()

            assigned_reviewer = str(
                record.get("assigned_reviewer") or ""
            ).strip()

            decision = updates.get("approval_decision")

            if record.get("review_stage", "first_review") != "awaiting_second_review":
                errors.append(
                    "This report is not waiting for a second-person review."
                )

            if (
                not second_reviewer
                or len(second_reviewer) > self.MAX_REVIEWER_LENGTH
            ):
                errors.append(
                    "Enter a reviewer name (max 60 characters)."
                )

            elif second_reviewer.casefold() != assigned_reviewer.casefold():
                errors.append(
                    "Only the assigned reviewer can approve or reject this review."
                )

            if decision not in ("approve", "reject"):
                errors.append("Choose approve or reject.")

            if decision == "reject" and not rejection_reason:
                errors.append("A rejection reason is required.")

        if errors:
            return record, errors

        updated = copy.deepcopy(record)

        if action == "first":

            first_reviewer = str(updates["reviewer"]).strip()

            updated["review_stage"] = "awaiting_second_review"
            updated["review_status"] = "Pending Review"
            updated["first_reviewed_by"] = first_reviewer
            updated["report_outcome"] = updates["report_outcome"]
            updated["risk_level"] = updates["risk_level"]
            updated["final_review_decision"] = ""
            updated["assigned_reviewer"] = reviewer

            updated.setdefault("review_history", []).append({
                "stage": "first",
                "reviewer": first_reviewer,
                "outcome": updates["report_outcome"],
                "risk_level": updates["risk_level"],
                "assigned_reviewer": reviewer
            })

        elif action == "second":

            second_reviewer = str(updates["reviewer"]).strip()
            decision = updates["approval_decision"]

            updated.setdefault("review_history", []).append({
                "stage": "second",
                "reviewer": second_reviewer,
                "decision": decision.title(),
                "rejection_reason": rejection_reason
            })

            if decision == "approve":

                updated["review_stage"] = "closed"
                updated["review_status"] = "Done"
                updated["final_review_decision"] = "Approved"

            else:

                updated["review_stage"] = "first_review"
                updated["review_status"] = "Pending Review"
                updated["first_reviewed_by"] = ""
                updated["report_outcome"] = ""
                updated["risk_level"] = ""
                updated["final_review_decision"] = "Rejected"
                updated["assigned_reviewer"] = ""

        elif status is not None:

            updated["review_status"] = status

        if action is None and override is not None:

            updated["priority"] = override

            updated["priority_overridden"] = (
                override != updated.get("system_priority")
            )

        if note:
            updated.setdefault("investigation_notes", []).append(note)

        if action is None and reviewer:
            updated["assigned_reviewer"] = reviewer

        return updated, []

    # ==========================================
    # 9. LOOKUP AND SORTING
    # ==========================================

    @staticmethod
    def find_record_index(records, report_id):

        wanted = (report_id or "").strip().upper()

        for index, record in enumerate(records or []):

            if (
                isinstance(record, dict)
                and str(record.get("report_id", "")).upper() == wanted
            ):
                return index

        return -1

    @classmethod
    def sort_records_by_priority(cls, records):

        return sorted(
            records,
            key=lambda record: (
                -cls.PRIORITY_RANK.get(record.get("priority"), 0),
                -record.get("risk_score", 0),
                str(record.get("report_id", ""))
            )
        )

    # ==========================================
    # 10. PASSWORD VERIFICATION
    # ==========================================

    @classmethod
    def hash_passcode(cls, password):

        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            cls.IT_PASSWORD_SALT.encode("utf-8"),
            cls.IT_PASSWORD_ITERATIONS
        ).hex()

    @classmethod
    def verify_it_password(cls, entered):

        override = os.environ.get("phishguard_it_password")

        expected = (
            cls.hash_passcode(override)
            if override
            else cls.IT_PASSWORD_HASH
        )

        return hmac.compare_digest(
            cls.hash_passcode(entered or ""),
            expected
        )