from datetime import datetime
from typing import Callable, Dict, List


class AuditTrail:
    """Keeps a dated list of who did what to a report, inside the report record."""

    TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(self, clock: Callable[[], datetime] = datetime.now):
        self._clock = clock

    def add_entry(self, record: Dict, action: str, reviewer_name: str, details: str = "") -> Dict:
        """Add one entry to the record's audit trail and return the record."""
        entry = {
            "timestamp": self._clock().strftime(self.TIME_FORMAT),
            "reviewer_name": reviewer_name,
            "action": action,
            "details": details,
        }
        record.setdefault("audit_trail", []).append(entry)
        return record

    def get_entries(self, record: Dict) -> List[Dict]:
        """A copy of the record's audit entries, oldest first (empty if there are none)."""
        return list(record.get("audit_trail", []))