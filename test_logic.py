import unittest

import logic_manager


def make_ai_result(**overrides):
    result = {
        "threat_level": "low",
        "confidence": 0.95,
        "impersonation": False,
        "urgency_manipulation": False,
        "credential_request": False,
        "suspicious_link": False,
        "attachment_risk": False,
    }
    result.update(overrides)
    return result


class LogicManagerTests(unittest.TestCase):
    def test_keyword_scan_finds_urgent_credential_request(self):
        result = logic_manager.scan_keywords("Urgent: verify your password")

        self.assertEqual(result["level"], "high")
        self.assertIn("urgent", result["found"]["urgency"])
        self.assertIn("password", result["found"]["credential"])

    def test_missing_ai_result_requires_manual_review(self):
        decision = logic_manager.apply_business_rules({}, None)

        self.assertEqual(decision["priority"], logic_manager.PRIORITY_MANUAL)

    def test_critical_threat_gets_critical_priority(self):
        decision = logic_manager.apply_business_rules(
            {},
            make_ai_result(threat_level="critical", confidence=0.9),
        )

        self.assertEqual(decision["priority"], logic_manager.PRIORITY_CRITICAL)

    def test_entered_information_escalates_to_urgent(self):
        report = {"actions_taken": {"entered_information": True}}
        decision = logic_manager.apply_business_rules(report, make_ai_result())

        self.assertEqual(decision["priority"], logic_manager.PRIORITY_URGENT)

    def test_next_report_id_uses_highest_valid_id(self):
        records = [
            {"report_id": "PG-0002"},
            {"report_id": "not-a-report-id"},
            {"report_id": "PG-0007"},
        ]

        self.assertEqual(logic_manager.next_report_id(records), "PG-0008")

if __name__ == "__main__":
    unittest.main()
