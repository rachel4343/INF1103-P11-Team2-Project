from typing import Dict, Optional, Tuple

from .priority_rule import PriorityRule


class LowThreatRule(PriorityRule):
    """
    Rule 5: Low threat can only be dismissed with very high confidence
    and no suspicious link.
    """

    PRIORITY = "Low Priority"
    _CONFIDENCE = 0.90

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        if (
            ai_result["threat_level"] == "low"
            and ai_result["confidence"] >= self._CONFIDENCE
            and not ai_result["suspicious_link"]
        ):
            reason = (
                f"{self.PRIORITY}, because the AI rated the threat low "
                f"({ai_result['confidence']:.0%} sure) "
                f"and found no suspicious link"
            )

            return self.PRIORITY, reason

        return None