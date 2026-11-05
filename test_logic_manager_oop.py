
import os

from logic_manager.logic_manager import LogicManager


def run_tests():

    logic = LogicManager()

    # ------------------------------------------
    # TEST 1: Risk Scoring
    # ------------------------------------------

    ai_result = {
        "threat_level": "high",
        "confidence": 0.90,
        "impersonation": True,
        "urgency_manipulation": True,
        "credential_request": True,
        "suspicious_link": True,
        "attachment_risk": False
    }

    score = logic.risk_score(ai_result)

    print("\nTEST 1: Risk Scoring")
    print("Risk score:", score)
    print("Breakdown:", logic.risk_breakdown(ai_result))

    assert score == 73

    print("PASSED")


    # ------------------------------------------
    # TEST 2: Priority Rules
    # ------------------------------------------

    report = {
        "actions_taken": {
            "clicked_link": False,
            "opened_attachment": False,
            "entered_information": False
        }
    }

    result = logic.apply_business_rules(report, ai_result)

    print("\nTEST 2: Priority Rules")
    print("Priority:", result["priority"])
    print("Rules triggered:", result["rules_triggered"])

    assert result["priority"] == "Urgent Security Review"

    print("PASSED")


    # ------------------------------------------
    # TEST 3: Employee Action Escalation
    # ------------------------------------------

    low_risk_ai = {
        "threat_level": "low",
        "confidence": 0.95,
        "impersonation": False,
        "urgency_manipulation": False,
        "credential_request": False,
        "suspicious_link": False,
        "attachment_risk": False
    }

    report_with_actions = {
        "actions_taken": {
            "clicked_link": False,
            "opened_attachment": False,
            "entered_information": True
        }
    }

    result = logic.apply_business_rules(
        report_with_actions,
        low_risk_ai
    )

    print("\nTEST 3: Employee Action Escalation")
    print("Priority:", result["priority"])

    assert result["priority"] == "Urgent Security Review"

    print("PASSED")


    # ------------------------------------------
    # TEST 4: Invalid AI Result
    # ------------------------------------------

    result = logic.apply_business_rules({}, None)

    print("\nTEST 4: Invalid AI Result")
    print("Priority:", result["priority"])

    assert result["priority"] == "Manual Review Required"

    print("PASSED")


    # ------------------------------------------
    # TEST 5: Report ID Generation
    # ------------------------------------------

    records = [
        {"report_id": "PG-0001"},
        {"report_id": "PG-0002"},
        {"report_id": "PG-0005"}
    ]

    next_id = logic.next_report_id(records)

    print("\nTEST 5: Report ID Generation")
    print("Next report ID:", next_id)

    assert next_id == "PG-0006"

    print("PASSED")


    # ------------------------------------------
    # TEST 6: Final Record Creation
    # ------------------------------------------

    final_record = logic.build_final_record(
        "PG-0006",
        report,
        ai_result
    )

    print("\nTEST 6: Final Record Creation")
    print("Report ID:", final_record["report_id"])
    print("Priority:", final_record["priority"])
    print("Risk score:", final_record["risk_score"])

    assert final_record["report_id"] == "PG-0006"
    assert final_record["risk_score"] == 73
    assert final_record["review_status"] == "Pending Review"
    assert "keyword_scan" not in final_record

    print("PASSED")


    # ------------------------------------------
    # TEST 7: Record Lookup
    # ------------------------------------------

    index = logic.find_record_index(
        [final_record],
        "pg-0006"
    )

    print("\nTEST 7: Record Lookup")
    print("Found at index:", index)

    assert index == 0

    print("PASSED")


    # ------------------------------------------
    # TEST 8: IT Password Verification
    # ------------------------------------------

    print("\nTEST 8: IT Password Verification")

    # Temporarily set a test password.
    os.environ["phishguard_it_password"] = "test-password-123"

    try:
        correct_password = logic.verify_it_password(
            "test-password-123"
        )

        incorrect_password = logic.verify_it_password(
            "wrong-password"
        )

        print("Correct password accepted:", correct_password)
        print("Incorrect password rejected:", not incorrect_password)

        assert correct_password is True
        assert incorrect_password is False

    finally:
        # Restore the original environment state.
        os.environ.pop("phishguard_it_password", None)

    print("PASSED")


    # ------------------------------------------
    # TEST 9: First-Person Review
    # ------------------------------------------

    review_record = logic.build_final_record(
        "PG-0010",
        report,
        ai_result
    )

    first_updates = {
        "review_action": "first",
        "reviewer": "Alice",
        "assigned_reviewer": "Bob",
        "report_outcome": "Resolved (real scam)",
        "risk_level": "High"
    }

    updated_record, errors = logic.apply_review_update(
        review_record,
        first_updates
    )

    print("\nTEST 9: First-Person Review")
    print("Errors:", errors)
    print("Review stage:", updated_record["review_stage"])
    print("Assigned reviewer:", updated_record["assigned_reviewer"])

    assert errors == []
    assert updated_record["review_stage"] == "awaiting_second_review"
    assert updated_record["assigned_reviewer"] == "Bob"
    assert updated_record["first_reviewed_by"] == "Alice"

    print("PASSED")


    # ------------------------------------------
    # TEST 10: Second-Person Approval
    # ------------------------------------------

    second_updates = {
        "review_action": "second",
        "reviewer": "Bob",
        "approval_decision": "approve"
    }

    updated_record, errors = logic.apply_review_update(
        updated_record,
        second_updates
    )

    print("\nTEST 10: Second-Person Approval")
    print("Errors:", errors)
    print("Review stage:", updated_record["review_stage"])
    print("Review status:", updated_record["review_status"])

    assert errors == []
    assert updated_record["review_stage"] == "closed"
    assert updated_record["review_status"] == "Done"
    assert updated_record["final_review_decision"] == "Approved"

    print("PASSED")


    # ------------------------------------------
    # TEST 11: Invalid Second Reviewer
    # ------------------------------------------

    invalid_updates = {
        "review_action": "second",
        "reviewer": "Charlie",
        "approval_decision": "approve"
    }

    unchanged_record, errors = logic.apply_review_update(
        updated_record,
        invalid_updates
    )

    print("\nTEST 11: Invalid Second Reviewer")
    print("Errors:", errors)

    assert len(errors) > 0
    assert unchanged_record == updated_record

    print("PASSED")


    # ------------------------------------------
    # TEST 12: Priority Sorting
    # ------------------------------------------

    records_to_sort = [
        {
            "report_id": "PG-0001",
            "priority": "Low Priority",
            "risk_score": 10
        },
        {
            "report_id": "PG-0002",
            "priority": "Critical",
            "risk_score": 90
        },
        {
            "report_id": "PG-0003",
            "priority": "Security Review",
            "risk_score": 50
        }
    ]

    sorted_records = logic.sort_records_by_priority(
        records_to_sort
    )

    print("\nTEST 12: Priority Sorting")

    for record in sorted_records:
        print(record["report_id"], record["priority"])

    assert sorted_records[0]["report_id"] == "PG-0002"
    assert sorted_records[1]["report_id"] == "PG-0003"
    assert sorted_records[2]["report_id"] == "PG-0001"

    print("PASSED")


    # ------------------------------------------
    # FINAL RESULT
    # ------------------------------------------

    print("\n========================================")
    print("ALL 12 TESTS PASSED!")
    print("========================================")


if __name__ == "__main__":
    run_tests()
