import json
from typing import Dict

DATA_FILE = "phishguard_reports.json"


def save_report(report: Dict, decision: Dict):
    records = []

    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            records = json.load(f)

    records.append({"report": report, "decision": decision})

    with open(DATA_FILE, "w") as f:
        json.dump(records, f, indent=2)