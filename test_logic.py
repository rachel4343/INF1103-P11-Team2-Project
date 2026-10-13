import unittest

import logic_manager


def make_ai_result(**overrides):
    """Create a valid hardcoded AI result for testing."""
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

    # ──────────────────────────────────────────────
    # 1. KEYWORD CHECKER
    # ──────────────────────────────────────────────

    def test_keyword_scan_finds_urgent_credential_request(self):
        result = logic_manager.scan_keywords(
            "Urgent: verify your password"
        )

        self.assertEqual(result["level"], "high")
        self.assertIn("urgent", result["found"]["urgency"])
        self.assertIn("password", result["found"]["credential"])

    def test_keyword_scan_safe_text(self):
        result = logic_manager.scan_keywords(
            "Tomorrow's lesson starts at 10am."
        )

        self.assertEqual(result["level"], "safe")
        self.assertEqual(result["score"], 0)

    def test_keyword_scan_does_not_match_partial_words(self):
        result = logic_manager.scan_keywords(
            "I know about shopping and accounting."
        )

        self.assertNotIn("now", result["found"]["urgency"])
        self.assertNotIn("pin", result["found"]["credential"])
        self.assertNotIn("account", result["found"]["credential"])

    # ──────────────────────────────────────────────
    # 2. AI RESULT VALIDATION
    # ──────────────────────────────────────────────

    def test_valid_ai_result_is_usable(self):
        ai_result = make_ai_result()

        self.assertTrue(
            logic_manager.has_usable_ai_result(ai_result)
        )

    def test_missing_ai_result_is_not_usable(self):
        self.assertFalse(
            logic_manager.has_usable_ai_result(None)
        )

    def test_invalid_confidence_is_not_usable(self):
        ai_result = make_ai_result(confidence=1.5)

        self.assertFalse(
            logic_manager.has_usable_ai_result(ai_result)
        )

    # ──────────────────────────────────────────────
    # 3. BUSINESS RULES
    # ──────────────────────────────────────────────

    def test_missing_ai_result_requires_manual_review(self):
        decision = logic_manager.apply_business_rules(
            {},
            None
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_MANUAL
        )

    def test_critical_threat_gets_critical_priority(self):
        ai_result = make_ai_result(
            threat_level="critical",
            confidence=0.90,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_CRITICAL
        )

    def test_credential_request_with_suspicious_link_is_urgent(self):
        ai_result = make_ai_result(
            threat_level="high",
            confidence=0.90,
            credential_request=True,
            suspicious_link=True,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_URGENT
        )

    def test_high_impersonation_and_urgency_gets_high_priority(self):
        ai_result = make_ai_result(
            threat_level="high",
            confidence=0.90,
            impersonation=True,
            urgency_manipulation=True,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_HIGH
        )

    def test_medium_threat_gets_security_review(self):
        ai_result = make_ai_result(
            threat_level="medium",
            confidence=0.80,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_SECURITY
        )

    def test_low_threat_gets_low_priority(self):
        ai_result = make_ai_result(
            threat_level="low",
            confidence=0.95,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_LOW
        )

    # ──────────────────────────────────────────────
    # 4. CONFIDENCE / CORROBORATION
    # ──────────────────────────────────────────────

    def test_low_confidence_medium_threat_requires_manual_review(self):
        ai_result = make_ai_result(
            threat_level="medium",
            confidence=0.50,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_MANUAL
        )

    def test_corroborating_indicators_allow_lower_confidence(self):
        ai_result = make_ai_result(
            threat_level="medium",
            confidence=0.70,
            impersonation=True,
            urgency_manipulation=True,
            attachment_risk=True,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_SECURITY
        )

    # ──────────────────────────────────────────────
    # 5. USER ACTION ESCALATION
    # ──────────────────────────────────────────────

    def test_entered_information_escalates_to_urgent(self):
        report = {
            "actions_taken": {
                "entered_information": True
            }
        }

        decision = logic_manager.apply_business_rules(
            report,
            make_ai_result()
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_URGENT
        )

    def test_clicked_suspicious_link_escalates_to_high(self):
        report = {
            "actions_taken": {
                "clicked_link": True
            }
        }

        ai_result = make_ai_result(
            suspicious_link=True
        )

        decision = logic_manager.apply_business_rules(
            report,
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_HIGH
        )

    # ──────────────────────────────────────────────
    # 6. RISK SCORE
    # ──────────────────────────────────────────────

    def test_risk_score_calculation(self):
        ai_result = make_ai_result(
            threat_level="high",
            credential_request=True,
            suspicious_link=True,
            impersonation=True,
        )

        score = logic_manager.risk_score(ai_result)

        # High = 40
        # Credential request = 10
        # Suspicious link = 10
        # Impersonation = 7
        # Total = 67
        self.assertEqual(score, 67)

    def test_risk_score_is_deterministic(self):
        ai_result = make_ai_result(
            threat_level="critical",
            credential_request=True,
            suspicious_link=True,
        )

        first_score = logic_manager.risk_score(ai_result)
        second_score = logic_manager.risk_score(ai_result)

        self.assertEqual(first_score, second_score)

    # ──────────────────────────────────────────────
    # 7. REPORT ID
    # ──────────────────────────────────────────────

    def test_next_report_id_uses_highest_valid_id(self):
        records = [
            {"report_id": "PG-0002"},
            {"report_id": "not-a-report-id"},
            {"report_id": "PG-0007"},
        ]

        self.assertEqual(
            logic_manager.next_report_id(records),
            "PG-0008"
        )

    def test_next_report_id_empty_records_starts_at_one(self):
        self.assertEqual(
            logic_manager.next_report_id([]),
            "PG-0001"
        )

    # ──────────────────────────────────────────────
    # 8. PRIORITY SELECTION
    # ──────────────────────────────────────────────

    def test_highest_priority_rule_wins(self):
        ai_result = make_ai_result(
            threat_level="critical",
            confidence=0.99,
            impersonation=True,
            urgency_manipulation=True,
            credential_request=True,
            suspicious_link=True,
        )

        decision = logic_manager.apply_business_rules(
            {},
            ai_result
        )

        self.assertEqual(
            decision["priority"],
            logic_manager.PRIORITY_CRITICAL
        )

        self.assertEqual(
            len(decision["rules_triggered"]),
            1
        )

    # ──────────────────────────────────────────────
    # 9. TWO-PERSON REVIEW
    # ──────────────────────────────────────────────

    def test_only_assigned_reviewer_can_approve(self):
        record = {
            "review_stage": "awaiting_second_review",
            "assigned_reviewer": "hu hai",
        }

        updates = {
            "review_action": "second",
            "reviewer": "someone else",
            "approval_decision": "approve",
        }

        updated, errors = logic_manager.apply_review_update(
            record,
            updates
        )

        self.assertIn(
            "Only the assigned reviewer can approve or reject this review.",
            errors
        )

        # Invalid update should leave the record unchanged
        self.assertEqual(updated, record)

    def test_assigned_reviewer_can_approve(self):
        record = {
            "review_stage": "awaiting_second_review",
            "review_status": "Pending Review",
            "assigned_reviewer": "hu hai",
            "review_history": [],
        }

        updates = {
            "review_action": "second",
            "reviewer": "hu hai",
            "approval_decision": "approve",
        }

        updated, errors = logic_manager.apply_review_update(
            record,
            updates
        )

        self.assertEqual(errors, [])
        self.assertEqual(updated["review_status"], "Done")
        self.assertEqual(updated["review_stage"], "closed")
        self.assertEqual(
            updated["final_review_decision"],
            "Approved"
        )


if __name__ == "__main__":
    unittest.main()