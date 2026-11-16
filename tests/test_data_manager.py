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
    assert outcome.get("duplicate") is None

def test_add_duplicate(data_mgr, sample_report):
    """Adding the same report twice should detect duplicate."""
    data_mgr.add_record(sample_report)
    outcome = data_mgr.add_record(sample_report)
    assert outcome.get("duplicate") is True