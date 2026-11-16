"""Tests for the RecordStore abstract interface and JsonRecordStore."""
import pytest
from data_manager.record_store import RecordStore
from data_manager.json_record_store import JsonRecordStore

def test_record_store_is_abstract():
    """RecordStore should be an abstract base class."""
    assert hasattr(RecordStore, '__abstractmethods__')

