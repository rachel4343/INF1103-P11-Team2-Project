"""Tests for the DataManager class."""
import pytest
from data_manager import DataManager, JsonRecordStore

@pytest.fixture
def data_mgr(temp_data_file):
    """Create a DataManager pointing to a temp file."""
    store = JsonRecordStore(temp_data_file)
    return DataManager(store)

def test_add_record(data_mgr, sample_report):
    """Adding a valid report should succeed."""
    outcome = data_mgr.add_record(sample_report)
    assert outcome.get("saved") is True
    # Accept both None or False — your code uses False
    assert outcome.get("duplicate") in (None, False)


def test_add_duplicate(data_mgr, sample_report):
    """Adding the same report twice should detect duplicate."""
    data_mgr.add_record(sample_report)
    outcome = data_mgr.add_record(sample_report)
    assert outcome.get("duplicate") is True

def test_search_records(data_mgr, sample_report):
    """Search should find matching records."""
    data_mgr.add_record(sample_report)
    
    results = data_mgr.search_records([sample_report], "Support")
    assert len(results) == 1
    
    results = data_mgr.search_records([sample_report], "nonexistent")
    assert len(results) == 0

def test_load_records_returns_list(data_mgr):
    """Loading records should always return a list."""
    records = data_mgr.load_records()
    assert isinstance(records, list)