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