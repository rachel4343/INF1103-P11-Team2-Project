"""Tests for the RecordStore abstract interface and JsonRecordStore."""
import pytest
from data_manager.record_store import RecordStore
from data_manager.json_record_store import JsonRecordStore

def test_record_store_is_abstract():
    """RecordStore should be an abstract base class."""
    assert hasattr(RecordStore, '__abstractmethods__')

def test_json_store_save_and_load(temp_data_file):
    """Saving records then loading them should return the same data."""
    store = JsonRecordStore(temp_data_file)
    records = [{"id": 1, "data": "test"}, {"id": 2, "data": "sample"}]
    
    assert store.save_all(records) is True
    loaded = store.load_all()
    
    assert len(loaded) == 2
    assert loaded[0]["id"] == 1
    assert loaded[1]["data"] == "sample"

def test_json_store_file_not_exists(temp_data_file):
    """Loading from a non-existent file should return empty list."""
    # Delete the temp file first
    if temp_data_file.exists():
        temp_data_file.unlink()
    
    store = JsonRecordStore(temp_data_file)
    records = store.load_all()
    assert records == []    