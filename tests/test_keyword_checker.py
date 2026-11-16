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