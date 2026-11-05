# action_escalator.py under logic_manager.py
# This module contains the ActionEscalator class, which is responsible for escalating the priority of a report based on employee actions and AI analysis results.
# The ActionEscalator class reads employee actions from a report, evaluates them against the AI analysis results, and escalates the priority of the report if necessary. 
# It ensures that any risky actions taken by employees are appropriately reflected in the priority level for further review or action.


class ActionEscalator:

    PRIORITY_RANK = {
        "Critical": 6,
        "Urgent Security Review": 5,
        "High-Priority Review": 4,
        "Security Review": 3,
        "Manual Review Required": 2,
        "Low Priority": 1
    }

    def read_actions(self, report):
        """Read employee actions from modern or legacy report formats."""

        actions_taken = report.get("actions_taken", {})

        if isinstance(actions_taken, dict):
            clicked_link = bool(actions_taken.get("clicked_link", False))
            opened_attachment = bool(actions_taken.get("opened_attachment", False))
            entered_information = bool(actions_taken.get("entered_information", False))

        else:
            # Support the legacy string-based actions format.
            actions = report.get("actions", "")

            if not isinstance(actions, str):
                actions = ""

            actions = actions.lower()

            clicked_link = "clicked_link" in actions
            opened_attachment = "opened_attachment" in actions
            entered_information = "entered_information" in actions

        return {
            "clicked_link": clicked_link,
            "opened_attachment": opened_attachment,
            "entered_information": entered_information
        }

    def escalate(self, report, ai_result, priority, triggered):
        """Increase priority when employee actions indicate additional risk."""

        actions = self.read_actions(report)

        # Entering information raises priority to at least Urgent.
        if actions["entered_information"]:
            if self.PRIORITY_RANK[priority] < self.PRIORITY_RANK["Urgent Security Review"]:
                priority = "Urgent Security Review"

            triggered.append(
                "Employee entered information, requiring urgent security review."
            )

        # Clicking a suspicious link raises priority to at least High.
        if actions["clicked_link"] and ai_result.get("suspicious_link", False):
            if self.PRIORITY_RANK[priority] < self.PRIORITY_RANK["High-Priority Review"]:
                priority = "High-Priority Review"

            triggered.append(
                "Employee clicked a suspicious link, increasing priority."
            )

        # Opening a risky attachment raises priority to at least High.
        if actions["opened_attachment"] and ai_result.get("attachment_risk", False):
            if self.PRIORITY_RANK[priority] < self.PRIORITY_RANK["High-Priority Review"]:
                priority = "High-Priority Review"

            triggered.append(
                "Employee opened a risky attachment, increasing priority."
            )

        return priority
