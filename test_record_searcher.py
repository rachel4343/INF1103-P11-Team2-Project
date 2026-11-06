import unittest

from data_manager.record_searcher import RecordSearcher


def make_record(report_id, priority="Low Priority", risk=0, **report):
    base = {"viewed": True, "subject": "", "body": ""}
    base.update(report)
    return {"report_id": report_id, "priority": priority, "risk_score": risk,
            "threat_level": "low", "review_status": "Pending Review", "report": base}


class RecordSearcherTests(unittest.TestCase):

    def setUp(self):
        self.searcher = RecordSearcher()
        self.records = [
            make_record("PG-0001", "Critical", 93, subject="URGENT: verify your password",
                        sender_email="help@paypa1-support.com", urls=["http://bit.ly/verify-now"],
                        actions_taken={"clicked_link": True}),
            make_record("PG-0002", subject="Lunch on Friday", body="Shall we meet at noon?"),
            make_record("PG-0003", "Critical", 100, subject="Invoice overdue", viewed=False,
                        attachments=["invoice.exe"]),
        ]

    def ids(self, records):
        return [record["report_id"] for record in records]

    def test_search_needs_every_word_in_any_letter_case(self):
        self.assertEqual(self.ids(self.searcher.search_records(self.records, "URGENT password")), ["PG-0001"])
        self.assertEqual(self.ids(self.searcher.search_records(self.records, "urgent lunch")), [])

    def test_search_looks_in_links_attachments_and_senders(self):
        self.assertEqual(self.ids(self.searcher.search_records(self.records, "bit.ly")), ["PG-0001"])
        self.assertEqual(self.ids(self.searcher.search_records(self.records, "invoice.exe")), ["PG-0003"])
        self.assertEqual(self.ids(self.searcher.search_records(self.records, "paypa1")), ["PG-0001"])

    def test_empty_search_returns_everything(self):
        self.assertEqual(len(self.searcher.search_records(self.records, "")), 3)
        self.assertEqual(len(self.searcher.search_records(self.records, None)), 3)

    def test_filter_by_text_ignores_letter_case(self):
        found = self.searcher.filter_records(self.records, priority="critical")
        self.assertEqual(self.ids(found), ["PG-0001", "PG-0003"])

    def test_filter_by_risk_range_and_viewed_and_user_acted(self):
        self.assertEqual(self.ids(self.searcher.filter_records(self.records, min_risk=95)), ["PG-0003"])
        self.assertEqual(self.ids(self.searcher.filter_records(self.records, max_risk=10)), ["PG-0002"])
        self.assertEqual(self.ids(self.searcher.filter_records(self.records, viewed=False)), ["PG-0003"])
        self.assertEqual(self.ids(self.searcher.filter_records(self.records, user_acted=True)), ["PG-0001"])

    def test_filters_combine_and_none_is_ignored(self):
        found = self.searcher.filter_records(self.records, priority="Critical", min_risk=95, viewed=None)
        self.assertEqual(self.ids(found), ["PG-0003"])

    def test_unknown_filter_name_is_rejected(self):
        with self.assertRaises(ValueError):
            self.searcher.filter_records(self.records, colour="red")

    def test_find_record_ignores_letter_case_and_returns_none_when_missing(self):
        self.assertEqual(self.searcher.find_record(self.records, " pg-0002 ")["report_id"], "PG-0002")
        self.assertIsNone(self.searcher.find_record(self.records, "PG-9999"))

    def test_count_by_counts_biggest_group_first(self):
        counts = self.searcher.count_by(self.records, "priority")
        self.assertEqual(counts, {"Critical": 2, "Low Priority": 1})
        self.assertEqual(list(counts)[0], "Critical")

    def test_damaged_records_are_ignored_not_fatal(self):
        damaged = self.records + ["oops", 5, {"report": "not a dict", "risk_score": "x"}]
        self.assertEqual(len(self.searcher.search_records(damaged, "")), 4)
        self.assertEqual(len(self.searcher.filter_records(damaged, min_risk=50)), 2)
        self.assertEqual(sum(self.searcher.count_by(damaged, "priority").values()), 4)


if __name__ == "__main__":
    unittest.main()