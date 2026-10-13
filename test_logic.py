import unittest

import logic_manager


def make_ai_result(**overrides):
    result = {
        "threat_level": "low",
        "confidence": 0.95,
        "impersonation": False,
        "urgency_manipulation": False,
        "credential_request": False,
        "suspicious_link": False,
        "attachment_risk": False,
    }
    result.update(overrides)
    return result


