# ==============================================
#  PHISHGUARD — Data Manager
#  INF1103 Team Project
# ==============================================

import json
import os
import time
from typing import Dict

DATA_FILE = "phishguard_reports.json"

def load_records():
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

def save_records(records):
    """Write to a temp file, then swap it in so a crash can't leave a half-written file."""
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(records, f, indent=2)
    os.replace(tmp, DATA_FILE)

def _scam_text(report: Dict) -> str:
    """Subject and body reduced to lowercase letters, so small edits don't hide the same scam."""
    if not report.get("viewed"):
        return ""
    text = f"{report.get('subject', '')} {report.get('body', '')}".lower()
    return "".join(c for c in text if c.isalpha())

def save_report(report: Dict, decision: Dict):
    """Save a report to the JSON file, skipping duplicates and flagging repeat scams."""
    records = load_records()
 
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
    save_records(records)
 
    print(f"\n Saved! Total reports: {len(records)}")
    print(f"   File: {DATA_FILE}")
    if same_scam:
        print(f"   Note: this scam was reported {same_scam} time(s) before")

EXACT_FILTERS = ("priority", "threat_level", "attack_type", "review_status",
                 "review_stage", "assigned_reviewer", "first_reviewed_by")
OTHER_FILTERS = ("viewed", "user_acted", "min_risk", "max_risk")


def _report(record: Dict) -> Dict:
    """The employee's report inside a record, or an empty dict if it is missing or malformed."""
    report = record.get("report")
    return report if isinstance(report, dict) else {}


def _as_list(value) -> list:
    """Make sure links and attachments are always handled as a list."""
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value] if value else []


def _search_text(record: Dict) -> str:
    """Everything a person might search for in one record, joined into one lowercase string."""
    report = _report(record)
    parts = [
        record.get("report_id"), record.get("attack_type"),
        record.get("assigned_reviewer"), record.get("first_reviewed_by"),
        report.get("sender_name"), report.get("sender_email"),
        report.get("subject"), report.get("body"), report.get("reason_for_suspicion"),
    ]
    parts += _as_list(report.get("urls")) + _as_list(report.get("attachments"))
    return " ".join(str(p) for p in parts if p).lower()


def search_records(records: list, text: str) -> list:
    """Records that contain every word of text, in any letter case, in the ID, sender,
    subject, body, reason, links, attachments, attack type or reviewer. Empty text returns all."""
    words = str(text or "").lower().split()
    return [r for r in records if isinstance(r, dict) and all(w in _search_text(r) for w in words)]

def _risk(record: Dict) -> float:
    try:
        return float(record.get("risk_score", 0))
    except (TypeError, ValueError):
        return 0.0


def _user_acted(record: Dict) -> bool:
    """True if the employee clicked a link, opened an attachment or entered information."""
    actions = _report(record).get("actions_taken")
    return isinstance(actions, dict) and any(actions.values())


def _matches(record: Dict, key: str, value) -> bool:
    if key in EXACT_FILTERS:
        return str(record.get(key, "")).strip().lower() == str(value).strip().lower()
    if key == "viewed":
        return bool(_report(record).get("viewed")) == bool(value)
    if key == "user_acted":
        return _user_acted(record) == bool(value)
    if key == "min_risk":
        return _risk(record) >= value
    return _risk(record) <= value


def filter_records(records: list, **criteria) -> list:
    """Records that match every criterion given. A criterion set to None is ignored.
    Text filters (not case sensitive): priority, threat_level, attack_type, review_status,
    review_stage, assigned_reviewer, first_reviewed_by.
    Other filters: viewed (True/False), user_acted (True/False), min_risk, max_risk."""
    unknown = set(criteria) - set(EXACT_FILTERS) - set(OTHER_FILTERS)
    if unknown:
        raise ValueError(f"Unknown filter: {', '.join(sorted(unknown))}")
    active = {k: v for k, v in criteria.items() if v is not None}
    return [r for r in records
            if isinstance(r, dict) and all(_matches(r, k, v) for k, v in active.items())]