from typing import Dict, Optional, Tuple

from .priority_rule import PriorityRule


class CriticalThreatRule(PriorityRule):
    """Rule 1: Critical threat with sufficient AI confidence."""

    PRIORITY = "Critical"
    _CONFIDENCE = 0.85
    _CORROBORATED_CONFIDENCE = 0.75

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        gate = self.confidence_gate(
            ai_result,
            self._CONFIDENCE,
            self._CORROBORATED_CONFIDENCE
        )

        if ai_result["threat_level"] == "critical" and gate:
            reason = (
                f"{self.PRIORITY}, because the AI rated the "
                f"threat critical ({gate})"
            )

            return self.PRIORITY, reason

        return None