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
    records = _load()
 
    for r in records:
        if r.get("report") == report:
            print("\n Duplicate report - already saved, not added again.")
            return
 
    scam = _scam_text(report)
    same_scam = sum(1 for r in records if scam and _scam_text(r.get("report") or {}) == scam)
 
    records.append({
        "viewed_email": report["viewed"],
        "report": report,
        "decision": decision,
        "status": "Pending Review",
        "report_id": f"R{len(records) + 1:03d}",
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "same_scam_before": same_scam
    })
    _write(records)
 
    print(f"\n Saved! Total reports: {len(records)}")
    print(f"   File: {DATA_FILE}")
    if same_scam:
        print(f"   Note: this scam was reported {same_scam} time(s) before")