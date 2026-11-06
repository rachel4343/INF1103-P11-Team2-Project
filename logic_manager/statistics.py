from typing import Dict, List

def generate_statistics(records: List) -> Dict:
    stats = {
        
        "total": len(records),
        "pending": 0,
        "awaiting_second": 0,
        "close_approved": 0,
        "close_rejected": 0,
        "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0}
    
    }

    for rec in records:
        stage = rec.get("review_stage", "Pending Review")
        threat = rec.get("threat_level", "low")

        if stage == "Pending Review":
            stats["pending"] += 1
        elif stage == "Awaiting Second Review":
            stats["awaiting_second"] += 1
        elif stage == "closed":
            if rec.get("final_outcome") == "approved":
                stats["close_approved"] += 1
            else:
                stats["close_rejected"] += 1

