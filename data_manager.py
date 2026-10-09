import json
import os
import time
from typing import Dict

DATA_FILE = "phishguard_reports.json"

def _load():
    """Read saved reports; keep an unreadable file as a backup instead of wiping it."""
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    backup = f"{DATA_FILE}.corrupt-{time.strftime('%Y%m%d%H%M%S')}"
    try:
        os.replace(DATA_FILE, backup)
        print(f"\n Warning: unreadable data file, kept as {backup}")
    except OSError:
        pass
    return []

def _write(records):
    """Write to a temp file, then swap it in so a crash can't leave a half-written file."""
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(records, f, indent=2)
    os.replace(tmp, DATA_FILE)

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