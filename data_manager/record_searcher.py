from typing import Dict, List, Optional


class RecordSearcher:
    """Searches, filters, finds and counts report records.

    It only reads the list it is given, so it never touches the saved file.
    """

    EXACT_FILTERS = ("priority", "threat_level", "attack_type", "review_status",
                     "review_stage", "assigned_reviewer", "first_reviewed_by")
    OTHER_FILTERS = ("viewed", "user_acted", "min_risk", "max_risk")

    def search_records(self, records: List[Dict], text: str) -> List[Dict]:
        """Records that contain every word of text, in any letter case, in the ID, sender,
        subject, body, reason, links, attachments, attack type or reviewer. Empty text returns all."""
        words = str(text or "").lower().split()
        found = []
        for record in records:
            if not isinstance(record, dict):
                continue
            haystack = self._search_text(record)
            if all(word in haystack for word in words):
                found.append(record)
        return found

    def filter_records(self, records: List[Dict], **criteria) -> List[Dict]:
        """Records that match every criterion given. A criterion set to None is ignored.
        Text filters (not case sensitive): priority, threat_level, attack_type, review_status,
        review_stage, assigned_reviewer, first_reviewed_by.
        Other filters: viewed (True/False), user_acted (True/False), min_risk, max_risk."""
        unknown = set(criteria) - set(self.EXACT_FILTERS) - set(self.OTHER_FILTERS)
        if unknown:
            raise ValueError(f"Unknown filter: {', '.join(sorted(unknown))}")
        active = {key: value for key, value in criteria.items() if value is not None}
        return [record for record in records
                if isinstance(record, dict)
                and all(self._matches(record, key, value) for key, value in active.items())]

    def find_record(self, records: List[Dict], report_id: str) -> Optional[Dict]:
        """The record with this report ID (any letter case), or None."""
        wanted = str(report_id).strip().upper()
        for record in records:
            if isinstance(record, dict) and str(record.get("report_id", "")).upper() == wanted:
                return record
        return None

    def count_by(self, records: List[Dict], field: str) -> Dict[str, int]:
        """How many records have each value of a field, biggest group first.
        Example: count_by(records, "priority") -> {"Critical": 3, "Low Priority": 2}"""
        counts = {}
        for record in records:
            if isinstance(record, dict):
                value = str(record.get(field) or "(blank)")
                counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    @staticmethod
    def _report(record: Dict) -> Dict:
        """The employee's report inside a record, or an empty dict if it is missing or malformed."""
        report = record.get("report")
        return report if isinstance(report, dict) else {}

    @staticmethod
    def _as_list(value) -> list:
        """Make sure links and attachments are always handled as a list."""
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value] if value else []

    def _search_text(self, record: Dict) -> str:
        """Everything a person might search for in one record, as one lowercase string."""
        report = self._report(record)
        parts = [
            record.get("report_id"), record.get("attack_type"),
            record.get("assigned_reviewer"), record.get("first_reviewed_by"),
            report.get("sender_name"), report.get("sender_email"),
            report.get("subject"), report.get("body"), report.get("reason_for_suspicion"),
        ]
        parts += self._as_list(report.get("urls")) + self._as_list(report.get("attachments"))
        return " ".join(str(part) for part in parts if part).lower()

    @staticmethod
    def _risk(record: Dict) -> float:
        try:
            return float(record.get("risk_score", 0))
        except (TypeError, ValueError):
            return 0.0

    def _user_acted(self, record: Dict) -> bool:
        """True if the employee clicked a link, opened an attachment or entered information."""
        actions = self._report(record).get("actions_taken")
        return isinstance(actions, dict) and any(actions.values())

    def _matches(self, record: Dict, key: str, value) -> bool:
        if key in self.EXACT_FILTERS:
            return str(record.get(key, "")).strip().lower() == str(value).strip().lower()
        if key == "viewed":
            return bool(self._report(record).get("viewed")) == bool(value)
        if key == "user_acted":
            return self._user_acted(record) == bool(value)
        if key == "min_risk":
            return self._risk(record) >= value
        return self._risk(record) <= value