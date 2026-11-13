import copy
from typing import Dict, List, Optional

from .record_store import RecordStore


class MemoryRecordStore(RecordStore):
    """Keeps reports in memory only. Nothing is written to disk, which makes it
    handy for tests and demos."""

    def __init__(self, records: Optional[List[Dict]] = None):
        super().__init__()
        self.__records = copy.deepcopy(records) if records else []

    def load_all(self) -> List[Dict]:
        return copy.deepcopy(self.__records)

    def save_all(self, records: List[Dict]) -> bool:
        self.__records = copy.deepcopy(records)
        return True