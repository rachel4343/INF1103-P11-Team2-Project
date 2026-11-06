# priority_rules.py under logic_manager.py
# This module contains the five priority rules used by the PhishGuard system to evaluate AI analysis results and determine the appropriate priority level for a report.
# Each rule is implemented as a subclass of the abstract base class PriorityRule, which defines the interface for evaluating AI results and counting warning indicators.
# The rules are:
# 1. CriticalThreatRule: Matches when the AI rates the threat as critical with sufficient confidence.
# 2. CredentialLinkRule: Matches when the email requests credentials through a suspicious link, with sufficient confidence.
# 3. HighThreatRule: Matches when the AI rates the threat as high and either finds impersonation and urgency manipulation, or at least three warning indicators.
# 4. MediumThreatRule: Matches when the AI rates the threat as medium with sufficient confidence.
# 5. LowThreatRule: Matches when the AI rates the threat as low with very high confidence and no suspicious link.
# Overall, these rules provide a structured approach to prioritizing reports based on AI analysis and employee actions, ensuring that critical threats are addressed promptly while minimizing false positives.


from typing import Dict, Optional, Tuple

from .priority_rule import PriorityRule


# Priority labels

PRIORITY_URGENT = "Urgent Security Review"
PRIORITY_HIGH = "High-Priority Review"
PRIORITY_SECURITY = "Security Review"
PRIORITY_LOW = "Low Priority"


# Confidence thresholds



CONF_CREDENTIAL_LINK = 0.80
CONF_CREDENTIAL_LINK_CORROBORATED = 0.70

CONF_MEDIUM = 0.75
CONF_MEDIUM_CORROBORATED = 0.65

CONF_LOW = 0.90

CORROBORATION_MIN_INDICATORS = 3




class CredentialLinkRule(PriorityRule):
    """
    Rule 2: Credentials requested through a suspicious link.

    Both indicators must be true.
    """

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        gate = self.confidence_gate(
            ai_result,
            CONF_CREDENTIAL_LINK,
            CONF_CREDENTIAL_LINK_CORROBORATED
        )

        if (
            ai_result["credential_request"]
            and ai_result["suspicious_link"]
            and gate
        ):
            reason = (
                f"{PRIORITY_URGENT}, because the email asks for "
                f"credentials through a suspicious link ({gate})"
            )

            return PRIORITY_URGENT, reason

        return None


class HighThreatRule(PriorityRule):
    """
    Rule 3: High threat supported by multiple warning indicators.

    Matches when:
    - Impersonation AND urgency manipulation are both true, OR
    - At least three warning indicators are true.
    """

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        if ai_result["threat_level"] == "high":

            indicators = self.count_indicators(ai_result)

            if (
                ai_result["impersonation"]
                and ai_result["urgency_manipulation"]
            ):
                reason = (
                    f"{PRIORITY_HIGH}, because the AI rated the threat "
                    f"high and found impersonation and urgency pressure"
                )

                return PRIORITY_HIGH, reason

            elif indicators >= CORROBORATION_MIN_INDICATORS:
                reason = (
                    f"{PRIORITY_HIGH}, because the AI rated the threat "
                    f"high and found {indicators} warning signs"
                )

                return PRIORITY_HIGH, reason

        return None


class MediumThreatRule(PriorityRule):
    """Rule 4: Medium threat with sufficient AI confidence."""

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        gate = self.confidence_gate(
            ai_result,
            CONF_MEDIUM,
            CONF_MEDIUM_CORROBORATED
        )

        if ai_result["threat_level"] == "medium" and gate:
            reason = (
                f"{PRIORITY_SECURITY}, because the AI rated the "
                f"threat medium ({gate})"
            )

            return PRIORITY_SECURITY, reason

        return None


class LowThreatRule(PriorityRule):
    """
    Rule 5: Low threat can only be dismissed with very high confidence
    and no suspicious link.
    """

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        if (
            ai_result["threat_level"] == "low"
            and ai_result["confidence"] >= CONF_LOW
            and not ai_result["suspicious_link"]
        ):
            reason = (
                f"{PRIORITY_LOW}, because the AI rated the threat low "
                f"({ai_result['confidence']:.0%} sure) "
                f"and found no suspicious link"
            )

            return PRIORITY_LOW, reason

        return None
