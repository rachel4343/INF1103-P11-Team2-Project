# risk_scorer.py under logic_manager.py
# This module contains the RiskScorer class, which calculates a risk score for a report based on the AI analysis results.
# The risk score is determined by assigning points to the AI threat level and each warning indicator that is present in the report.
# The RiskScorer class provides methods to calculate the total risk score and to generate a detailed breakdown of how the score was derived, 
# including the contribution of each indicator and the overall threat level.
# Overall, the RiskScorer class provides a quantitative measure of risk that can be used to prioritize reports and guide further investigation or action.


class RiskScorer:
    # Points assigned to each AI threat level.
    THREAT_POINTS = {
        "low": 0,
        "medium": 20,
        "high": 40,
        "critical": 60
    }

    # Points assigned to each warning indicator.
    INDICATOR_POINTS = {
        "credential_request": 10,
        "suspicious_link": 10,
        "impersonation": 7,
        "attachment_risk": 7,
        "urgency_manipulation": 6
    }

    # Human-readable names for the indicators.
    INDICATOR_LABELS = {
        "credential_request": "Credential Request",
        "suspicious_link": "Suspicious Link",
        "impersonation": "Impersonation",
        "attachment_risk": "Attachment Risk",
        "urgency_manipulation": "Urgency Manipulation"
    }
    

    def calculate_score(self, ai_result):
        """Calculate the total risk score."""

        threat_level = ai_result["threat_level"]

        # Start with the points assigned to the threat level.
        score = self.THREAT_POINTS[threat_level]

        # Add points for every indicator that is True.
        for indicator, points in self.INDICATOR_POINTS.items():
            if ai_result.get(indicator):
                score += points

        return score

    def get_breakdown(self, ai_result):
        """Return a breakdown showing how the risk score was calculated."""

        threat_level = ai_result["threat_level"]

        breakdown = {
            "threat_level": threat_level,
            "threat_points": self.THREAT_POINTS[threat_level],
            "indicators": {}
        }

        # Record the points contributed by each indicator.
        for indicator, points in self.INDICATOR_POINTS.items():
            if ai_result.get(indicator):
                breakdown["indicators"][indicator] = {
                    "label": self.INDICATOR_LABELS[indicator],
                    "points": points
                }

        breakdown["total_score"] = self.calculate_score(ai_result)

        return breakdown
