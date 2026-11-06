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