import json
from typing import Dict

DATA_FILE = "phishguard_reports.json"


def save_report(report: Dict, decision: Dict):
    with open(DATA_FILE, "w") as f:
        json.dump({"report": report, "decision": decision}, f, indent=2)