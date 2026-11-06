from typing import Dict, Optional, Tuple

from .priority_rule import PriorityRule


class MediumThreatRule(PriorityRule):
    """Rule 4: Medium threat with sufficient AI confidence."""

    PRIORITY = "Security Review"
    _CONFIDENCE = 0.75
    _CORROBORATED_CONFIDENCE = 0.65

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        gate = self.confidence_gate(
            ai_result,
            self._CONFIDENCE,
            self._CORROBORATED_CONFIDENCE
        )

        if ai_result["threat_level"] == "medium" and gate:
            reason = (
                f"{self.PRIORITY}, because the AI rated the "
                f"threat medium ({gate})"
            )

            return self.PRIORITY, reason

        return None