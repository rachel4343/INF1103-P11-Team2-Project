from typing import Dict, Optional, Tuple

from .priority_rule import PriorityRule


class HighThreatRule(PriorityRule):
    """
    Rule 3: High threat supported by multiple warning indicators.

    Matches when:
    - Impersonation AND urgency manipulation are both true, OR
    - At least three warning indicators are true.
    """

    PRIORITY = "High-Priority Review"
    _CORROBORATION_MIN_INDICATORS = 3

    def evaluate(self, ai_result: Dict) -> Optional[Tuple[str, str]]:

        if ai_result["threat_level"] == "high":

            indicators = self.count_indicators(ai_result)

            if (
                ai_result["impersonation"]
                and ai_result["urgency_manipulation"]
            ):
                reason = (
                    f"{self.PRIORITY}, because the AI rated the threat "
                    f"high and found impersonation and urgency pressure"
                )

                return self.PRIORITY, reason

            elif indicators >= self._CORROBORATION_MIN_INDICATORS:
                reason = (
                    f"{self.PRIORITY}, because the AI rated the threat "
                    f"high and found {indicators} warning signs"
                )

                return self.PRIORITY, reason

        return None