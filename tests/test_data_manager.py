"""Tests for the DataManager class."""
import pytest
from data_manager import DataManager, JsonRecordStore

@pytest.fixture
def data_mgr(temp_data_file):
    """Create a DataManager pointing to a temp file."""
    store = JsonRecordStore(temp_data_file)
    return DataManager(store)