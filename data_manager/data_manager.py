import time
from typing import Dict, List, Optional

from .record_searcher import RecordSearcher
from .record_store import RecordStore


class DataManager:
    """Saves and loads reports, skips duplicates, flags repeat scams, and answers queries.

    It is given a RecordStore to keep the reports in (aggregation: the store exists
    on its own) and creates its own RecordSearcher (composition).
    """

    def __init__(self, store: RecordStore):
        self.__store = store
        self.__searcher = RecordSearcher()

    def load_records(self) -> List[Dict]:
        return self.__store.load_all()

    def save_records(self, records: List[Dict]) -> bool:
        return self.__store.save_all(records)

    def add_record(self, record: Dict) -> Dict:
        """Save one new record unless the same report is already saved.

        Returns {"saved", "duplicate", "same_scam_before"}. same_scam_before is how
        many saved reports had the same subject and body apart from small edits.
        """
        records = self.load_records()
        report = record.get("report") or {}

        if any(isinstance(saved, dict) and saved.get("report") == report for saved in records):
            return {"saved": False, "duplicate": True, "same_scam_before": 0}

        same_scam = self._count_same_scam(records, report)
        record["same_scam_before"] = same_scam
        record.setdefault("saved_at", time.strftime("%Y-%m-%d %H:%M:%S"))
        records.append(record)
        return {"saved": self.save_records(records), "duplicate": False,
                "same_scam_before": same_scam}

    def search_records(self, records: List[Dict], text: str) -> List[Dict]:
        return self.__searcher.search_records(records, text)

    def filter_records(self, records: List[Dict], **criteria) -> List[Dict]:
        return self.__searcher.filter_records(records, **criteria)

    def find_record(self, records: List[Dict], report_id: str) -> Optional[Dict]:
        return self.__searcher.find_record(records, report_id)

    def count_by(self, records: List[Dict], field: str) -> Dict[str, int]:
        return self.__searcher.count_by(records, field)

    def take_warnings(self) -> List[str]:
        """Messages the screen should show (an unreadable file, a failed save)."""
        return self.__store.take_warnings()

    @staticmethod
    def _scam_text(report: Dict) -> str:
        """Subject and body reduced to lowercase letters, so small edits don't hide the same scam."""
        if not report.get("viewed"):
            return ""
        text = f"{report.get('subject', '')} {report.get('body', '')}".lower()
        return "".join(char for char in text if char.isalpha())

    def _count_same_scam(self, records: List[Dict], report: Dict) -> int:
        scam = self._scam_text(report)
        if not scam:
            return 0
        return sum(1 for saved in records
                   if isinstance(saved, dict)
                   and self._scam_text(saved.get("report") or {}) == scam)