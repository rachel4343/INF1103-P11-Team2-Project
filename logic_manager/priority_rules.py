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
PRIORITY_CRITICAL = "Critical"
PRIORITY_URGENT = "Urgent Security Review"
PRIORITY_HIGH = "High-Priority Review"
PRIORITY_SECURITY = "Security Review"
PRIORITY_LOW = "Low Priority"


# Confidence thresholds
CONF_CRITICAL = 0.85
CONF_CRITICAL_CORROBORATED = 0.75

CONF_CREDENTIAL_LINK = 0.80
CONF_CREDENTIAL_LINK_CORROBORATED = 0.70

CONF_MEDIUM = 0.75
CONF_MEDIUM_CORROBORATED = 0.65

CONF_LOW = 0.90

CORROBORATION_MIN_INDICATORS = 3

class CriticalThreatRule(PriorityRule):
    """Rule 1: Critical threat with sufficient AI confidence."""

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        gate = self.confidence_gate(
            ai_result,
            CONF_CRITICAL,
            CONF_CRITICAL_CORROBORATED
        )

        if ai_result["threat_level"] == "critical" and gate:
            reason = (
                f"{PRIORITY_CRITICAL}, because the AI rated the "
                f"threat critical ({gate})"
            )

            return PRIORITY_CRITICAL, reason

        return None