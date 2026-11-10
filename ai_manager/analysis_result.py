# analysis_result.py under ai_manager.py
# structure and store the final nalysis results

from dataclasses import dataclass, asdict
from typing import Dict

@dataclass
class AnalysisResult:
    """The AI assessment produced for one email."""

    threat_level: str
    attack_type: str
    confidence: float
    impersonation: bool
    urgency_manipulation: bool
    credential_request: bool
    suspicious_link: bool
    attachment_risk: bool
    recommended_action: str
    explanation: str

    def to_dict(self) -> Dict:
        return asdict(self)