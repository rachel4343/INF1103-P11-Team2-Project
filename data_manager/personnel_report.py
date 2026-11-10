import json
import os
import time
from typing import Dict, List

from .record_searcher import RecordSearcher

class PersonnelReport:
    stage_closed = "closed"

    def __init__(self):
        self.__searcher = RecordSearcher()

    def build_report(self, personnel: List[Dict], records: List[Dict]) -> Dict:
        rows = []
        for person in personnel:
            if not isinstance(person, dict):
                continue
            name = str(person.get("name") or "").strip()
            rows.append({
                "staff_id": person.get("staff_id"),
                "name": name,
                "role": person.get("role"),
                "department": person.get("department"),
                "active": person.get("active", True),
                "open_assigned_reports": self._open_assigned(records, name),
                "first_reviews_done": self._reviews_done(records, name, "first"),
                "second_reviews_done": self._reviews_done(records, name, "second")
            })
        return {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total personnel": len(rows),
            "total_records": len(records),
            "personnel": rows,
        }

    def save_report(self, personnel: List[Dict], records: List[Dict], path: str) -> bool:
        temp_path = path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as file:
                json.dump(self.build_report(personnel, records), file, indent=2)
            os.replace(temp_path, path)
            return True
        except (OSError, TypeError, ValueError):
            try:
                os.remove(temp_path)
            except OSError:
                pass
            return False

    def _open_assigned(self, records: List[Dict], name: str) -> int:
        if not name:
            return 0
        assigned = self.__searcher.filter_records(records, assigned_reviewer=name)
        return sum(1 for record in assigned
                   if str(record.get("review_stage") or "").strip().lower() != self.stage_closed)

    @staticmethod
    def _reviews_done(records: List[Dict], name: str, stage: str) -> int:
        if not name:
            return 0
        wanted, count = name.casefold(), 0
        for record in records:
            history = record.get("review_history") if isinstance(record, dict) else None
            for entry in history if isinstance(history, list) else []:
                if (isinstance(entry, dict) and entry.get("stage") == stage
                    and str(entry.get("reviewer") or "").strip().casefold() == wanted):
                    count += 1

            return count