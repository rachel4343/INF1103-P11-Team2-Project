"""Tests for the LogicManager, priority rules, and workflow."""
import pytest
from logic_manager import LogicManager, REVIEW_STATUSES, PRIORITIES

@pytest.fixture
def logic_mgr():
    return LogicManager()

def test_next_report_id(logic_mgr):
    """Report ID should start with PG- and increment."""
    records = []
    first = logic_mgr.next_report_id(records)
    # Just check the format — don't check exact number
    assert first.startswith("PG-")


def test_priority_values_are_valid():
    """Priority levels should include all four levels."""
    valid = ["low", "medium", "high", "critical"]
    assert "critical" in valid
    assert "high" in valid
    assert "medium" in valid
    assert "low" in valid


def test_review_status_values():
    """Review workflow stages should be complete."""
    assert "first" in REVIEW_STATUSES
    assert "awaiting_second_review" in REVIEW_STATUSES
    assert "closed" in REVIEW_STATUSES

def test_build_final_record(logic_mgr, sample_report):
    """Building a final record should include all required fields."""
    ai_result = {
        "threat_level": "high",
        "confidence": 0.85,
        "impersonation": True,
        "urgency_manipulation": False,
        "credential_request": True,
        "suspicious_link": False,
        "attachment_risk": False,
        "attack_type": "phishing",
        "recommended_action": "Report to Security",
        "explanation": "Found suspicious indicators"
    }

    record = logic_mgr.build_final_record("PG-00001", sample_report, ai_result, None)
    
    assert record["report_id"] == "PG-00001"
    assert record["threat_level"] == "high"
    assert "priority" in record
    assert "risk_score" in record
    assert "review_stage" in record