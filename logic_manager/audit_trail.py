from datetime import datetime
from typing import Dict, List

def add_audit_entry(record: Dict, action: str, reviewer_name: str, details: str = "") -> Dict:
    if "audit_trail" not in record:
        record["audit_trail"] = []

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reviewer_name": reviewer_name,
        "action": action,
        "details": details
    }