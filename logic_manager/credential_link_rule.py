from typing import Dict, Optional, Tuple

from .priority_rule import PriorityRule


class CredentialLinkRule(PriorityRule):
    """
    Rule 2: Credentials requested through a suspicious link.

    Both indicators must be true.
    """

    PRIORITY = "Urgent Security Review"
    _CONFIDENCE = 0.80
    _CORROBORATED_CONFIDENCE = 0.70

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        gate = self.confidence_gate(
            ai_result,
            self._CONFIDENCE,
            self._CORROBORATED_CONFIDENCE
        )

        if (
            ai_result["credential_request"]
            and ai_result["suspicious_link"]
            and gate
        ):
            reason = (
                f"{self.PRIORITY}, because the email asks for "
                f"credentials through a suspicious link ({gate})"
            )

            return self.PRIORITY, reason

        return None