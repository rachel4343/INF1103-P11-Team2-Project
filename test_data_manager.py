import unittest
 
from data_manager import DataManager
from data_manager.memory_record_store import MemoryRecordStore
from data_manager.record_store import RecordStore
 
 
def make_record(subject="Verify your account", body="Click the link now",
                viewed=True, report_id="PG-001"):
    """Create a small hardcoded record for testing."""
    return {
        "report_id": report_id,
        "report": {"subject": subject, "body": body, "viewed": viewed},
    }
 
 
class FailingStore(RecordStore):
    """A store whose save always fails, to test how DataManager reacts."""
 
    def load_all(self):
        return []
 
    def save_all(self, records):
        self._add_warning("Could not save reports")
        return False
 
 
class DataManagerTests(unittest.TestCase):
 
    def setUp(self):
        self.manager = DataManager(MemoryRecordStore())
 
    # ---- saving ----
    def test_new_record_is_saved(self):
        result = self.manager.add_record(make_record())
        self.assertTrue(result["saved"])
        self.assertFalse(result["duplicate"])
        self.assertEqual(len(self.manager.load_records()), 1)
 
    def test_saved_record_gets_timestamp(self):
        self.manager.add_record(make_record())
        self.assertIn("saved_at", self.manager.load_records()[0])
 
    # ---- exact duplicates ----
    def test_exact_duplicate_is_rejected(self):
        self.manager.add_record(make_record())
        result = self.manager.add_record(make_record(report_id="PG-002"))
        self.assertFalse(result["saved"])
        self.assertTrue(result["duplicate"])
        self.assertEqual(len(self.manager.load_records()), 1)
 
    # ---- repeat scams ----
    def test_first_report_has_no_earlier_matches(self):
        result = self.manager.add_record(make_record())
        self.assertEqual(result["same_scam_before"], 0)
 
    def test_similar_report_is_saved_and_counted(self):
        self.manager.add_record(make_record())
        similar = make_record(subject="VERIFY your account!!", report_id="PG-002")
        result = self.manager.add_record(similar)
        self.assertTrue(result["saved"])
        self.assertEqual(result["same_scam_before"], 1)
        self.assertEqual(len(self.manager.load_records()), 2)
 
    def test_different_report_is_not_counted(self):
        self.manager.add_record(make_record())
        other = make_record(subject="Lunch menu", body="Pizza on Friday", report_id="PG-002")
        result = self.manager.add_record(other)
        self.assertEqual(result["same_scam_before"], 0)
 
    def test_report_not_viewed_is_never_counted(self):
        self.manager.add_record(make_record(viewed=False))
        similar = make_record(subject="Verify your account!", viewed=False, report_id="PG-002")
        result = self.manager.add_record(similar)
        self.assertEqual(result["same_scam_before"], 0)
 
    # ---- failures and warnings ----
    def test_failed_save_is_reported(self):
        manager = DataManager(FailingStore())
        result = manager.add_record(make_record())
        self.assertFalse(result["saved"])
        self.assertEqual(manager.take_warnings(), ["Could not save reports"])
 
    def test_warnings_are_cleared_after_taking_them(self):
        manager = DataManager(FailingStore())
        manager.add_record(make_record())
        manager.take_warnings()
        self.assertEqual(manager.take_warnings(), [])
 
    # ---- hands work to the searcher ----
    def test_find_record_by_id(self):
        self.manager.add_record(make_record())
        records = self.manager.load_records()
        self.assertIsNotNone(self.manager.find_record(records, "PG-001"))
        self.assertIsNone(self.manager.find_record(records, "PG-999"))
 
    def test_search_records_finds_text(self):
        self.manager.add_record(make_record())
        records = self.manager.load_records()
        self.assertEqual(len(self.manager.search_records(records, "verify")), 1)
        self.assertEqual(len(self.manager.search_records(records, "pizza")), 0)
 
 
if __name__ == "__main__":
    unittest.main()