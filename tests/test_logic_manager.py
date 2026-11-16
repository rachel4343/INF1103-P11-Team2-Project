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