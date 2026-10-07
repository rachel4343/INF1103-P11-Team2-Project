import json
from typing import Dict

DATA_FILE = "phishguard_reports.json"


def save_report(report: Dict, decision: Dict):
    records = []

    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                records = json.load(f)
        except:
            records = []

    full_record = {
        "viewed_email": report["viewed"],
        "report": report,
        "decision": decision,
        "status": "Pending Review"
    }

    records.append(full_record)

    with open(DATA_FILE, "w") as f:
        json.dump(records, f, indent=2)

    print(f"\n Saved! Total reports: {len(records)}")
    print(f"   File: {DATA_FILE}")