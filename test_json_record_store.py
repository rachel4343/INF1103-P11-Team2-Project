import glob
import json
import os
import tempfile
import unittest
from unittest import mock

from data_manager.json_record_store import JsonRecordStore


class JsonRecordStoreTests(unittest.TestCase):

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = folder.name
        self.path = os.path.join(self.folder, "reports.json")
        self.store = JsonRecordStore(self.path)

    def test_missing_file_gives_empty_list(self):
        self.assertEqual(self.store.load_all(), [])
        self.assertEqual(self.store.take_warnings(), [])

    def test_save_then_load_round_trip_keeps_non_ascii_text(self):
        records = [{"report_id": "PG-0001", "report": {"subject": "Café – urgent"}}]

        self.assertTrue(self.store.save_all(records))

        self.assertEqual(JsonRecordStore(self.path).load_all(), records)

    def test_corrupt_file_is_kept_as_backup_and_empty_list_returned(self):
        with open(self.path, "w") as file:
            file.write("{not json")

        self.assertEqual(self.store.load_all(), [])

        backups = glob.glob(self.path + ".corrupt-*")
        self.assertEqual(len(backups), 1)
        self.assertFalse(os.path.exists(self.path))
        with open(backups[0]) as file:
            self.assertEqual(file.read(), "{not json")
        warnings = self.store.take_warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("kept as", warnings[0])

    def test_valid_json_that_is_not_a_list_is_treated_as_unreadable(self):
        with open(self.path, "w") as file:
            json.dump({"a": 1}, file)

        self.assertEqual(self.store.load_all(), [])
        self.assertEqual(len(glob.glob(self.path + ".corrupt-*")), 1)

    def test_failed_save_returns_false_with_a_warning_instead_of_crashing(self):
        store = JsonRecordStore(os.path.join(self.folder, "missing_folder", "reports.json"))

        self.assertFalse(store.save_all([{"report_id": "PG-0001"}]))

        warnings = store.take_warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("Could not save", warnings[0])

    def test_data_that_cannot_be_saved_leaves_no_temp_file_and_keeps_old_data(self):
        self.store.save_all([{"report_id": "PG-0001"}])

        self.assertFalse(self.store.save_all([{"report_id": "PG-0002", "bad": {1, 2}}]))

        self.assertFalse(os.path.exists(self.path + ".tmp"))
        self.assertEqual(self.store.load_all(), [{"report_id": "PG-0001"}])

    def test_path_comes_from_argument_then_environment_then_default(self):
        with mock.patch.dict(os.environ, {JsonRecordStore.PATH_VARIABLE: "from_env.json"}):
            self.assertEqual(JsonRecordStore("given.json").path, "given.json")
            self.assertEqual(JsonRecordStore().path, "from_env.json")
        with mock.patch.dict(os.environ, clear=True):
            self.assertEqual(JsonRecordStore().path, JsonRecordStore.DEFAULT_PATH)


if __name__ == "__main__":
    unittest.main()