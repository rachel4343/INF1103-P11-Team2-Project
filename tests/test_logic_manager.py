"""Tests for the LogicManager, priority rules, and workflow."""
import pytest
from logic_manager import LogicManager, REVIEW_STATUSES, PRIORITIES

@pytest.fixture
def logic_mgr():
    return LogicManager()

def test_next_report_id(logic_mgr):
    """Report ID should increment correctly."""
    records = []
    first = logic_mgr.next_report_id(records)
    assert first == "PG-00001"
    
    records.append({"report_id": first})
    second = logic_mgr.next_report_id(records)
    assert second == "PG-00002"

def test_priority_values_are_valid():
    """All priority levels should be defined."""
    assert "critical" in PRIORITIES
    assert "high" in PRIORITIES
    assert "medium" in PRIORITIES
    assert "low" in PRIORITIES

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