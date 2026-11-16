"""Tests for the offline KeywordChecker."""
import pytest
from io_manager.keyword_checker import KeywordChecker

@pytest.fixture
def checker():
    return KeywordChecker()

def test_detects_urgency(checker):
    """Urgency keywords should be detected."""
    text = "Act immediately or your account will be suspended."
    result = checker.scan(text)
    assert result["level"] in ["medium", "high", "critical"]
    assert len(result["found"]["urgency"]) > 0

def test_detects_credential_request(checker):
    """Password/login keywords should be detected."""
    text = "Please enter your password and login to verify your account."
    result = checker.scan(text)
    assert len(result["found"]["credential"]) > 0

def test_safe_text_returns_low_risk(checker):
    """Normal text should return low or safe risk."""
    text = "Thank you for your email. We will reply shortly."
    result = checker.scan(text)
    assert result["level"] in ["low", "safe"]

def test_empty_text(checker):
    """Empty text should not crash."""
    result = checker.scan("")
    assert isinstance(result["score"], int)