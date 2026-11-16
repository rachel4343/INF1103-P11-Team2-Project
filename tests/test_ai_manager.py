"""Tests for the AIManager — uses mock responses so no API needed."""
import pytest
from ai_manager import AIManager

@pytest.fixture
def ai_mgr():
    return AIManager()

def test_valid_response_schema(ai_mgr):
    """AI result with all required fields should validate successfully."""
    mock_response = {
        "threat_level": "high",
        "confidence": 0.85,
        "impersonation": True,
        "urgency_manipulation": True,
        "credential_request": False,
        "suspicious_link": True,
        "attachment_risk": False,
        "attack_type": "phishing",
        "recommended_action": "Report to Security",
        "explanation": "Multiple indicators detected"
    }

    is_valid = ai_mgr.ai_validator.validate(mock_response)
    assert is_valid is True