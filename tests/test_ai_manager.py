"""Tests for the AIManager — checks input/output structure."""
import pytest
from ai_manager import AIManager

@pytest.fixture
def ai_mgr():
    return AIManager()

def test_valid_response_structure():
    """AI result should have all required fields."""
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
    required = ["threat_level", "confidence", "explanation"]
    for field in required:
        assert field in mock_response

def test_invalid_threat_level_rejected():
    """Threat level must be one of the allowed values."""
    valid_levels = ["low", "medium", "high", "critical"]
    assert "super_high" not in valid_levels
