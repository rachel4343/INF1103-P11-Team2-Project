# threat_scorer.py under ai_manager.py
# getting the threat level result 

from typing import Dict, Tuple

from .config import Config

class ThreatScorer:
    """Turns detected indicators into a weighted score, threat level and confidence."""
    def score(self, signs: Dict[str, bool]) -> int:
        return sum(Config.WEIGHTS[k] for k, v in signs.items() if v)

    def assess(self, score: int) -> Tuple[str, float]:
        if score >= 8:
            return "critical", 0.90
        if score >= 5:
            return "high", 0.85
        if score >= 3:
            return "medium", 0.75
        if score >= 1:
            return "low", 0.65
        return "low", 0.95