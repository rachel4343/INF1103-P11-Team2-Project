# attack_classifier.py under ai_manager.py
# classifying types of attack based on indicator detected

from typing import Dict

class AttackClassifier:
    """Determines the primary attack type from the indicators."""

    def classify(self, signs: Dict[str, bool], score: int) -> str:
        if signs["credential_request"] or (signs["suspicious_link"] and signs["impersonation"]):
            return "Credential harvesting"
        if signs["attachment_risk"]:
            return "Malware delivery"
        if signs["impersonation"]:
            return "Executive impersonation"
        if score > 0:
            return "Suspicious spam"
        return "None"