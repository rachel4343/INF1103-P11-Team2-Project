from typing import Dict, List


class StatisticsReport:
    """Counts stored reports by review stage and threat level."""

    STAGE_FIRST_REVIEW = "first_review"
    STAGE_AWAITING_SECOND = "awaiting_second_review"
    STAGE_CLOSED = "closed"
    DECISION_APPROVED = "Approved"
    DECISION_REJECTED = "Rejected"
    THREAT_LEVELS = ("low", "medium", "high", "critical", "unknown")

    def generate(self, records: List[Dict]) -> Dict:
        """Return the counts. sent_back is part of pending: reports a second
        reviewer rejected, which are waiting for a new first review."""
        stats = {
            "total": 0,
            "pending": 0,
            "awaiting_second": 0,
            "close_approved": 0,
            "sent_back": 0,
            "risk_distribution": {level: 0 for level in self.THREAT_LEVELS},
        }

        for record in records or []:
            if not isinstance(record, dict):
                continue
            stats["total"] += 1
            self._count_stage(record, stats)

            threat = record.get("threat_level", "unknown")
            if threat in stats["risk_distribution"]:
                stats["risk_distribution"][threat] += 1

        return stats

    def _count_stage(self, record: Dict, stats: Dict) -> None:
        stage = record.get("review_stage", self.STAGE_FIRST_REVIEW)
        decision = record.get("final_review_decision")

        if stage == self.STAGE_FIRST_REVIEW:
            stats["pending"] += 1
            if decision == self.DECISION_REJECTED:
                stats["sent_back"] += 1
        elif stage == self.STAGE_AWAITING_SECOND:
            stats["awaiting_second"] += 1
        elif stage == self.STAGE_CLOSED and decision == self.DECISION_APPROVED:
            stats["close_approved"] += 1