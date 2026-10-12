# ==============================================
#  PHISHGUARD — Main
#  INF1103 Team Project
# ==============================================

import getpass
import json
import os
from typing import Dict, Optional, Tuple

import requests

import ai_manager
import data_manager
import io_manager
import logic_manager



API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"

# Never hard-code the key. Set it on your own machine:
#   Windows PowerShell : $env:GEMINI_API_KEY="your-key"
#   Mac / Linux        : export GEMINI_API_KEY=your-key
API_KEY = os.environ.get("GEMINI_API_KEY", "")

def ask_for_api_key() -> None:
    """Ask for the Gemini key at th startup. Typing is hidden and the key is kept
    in memory only: it is never written to a file or to the report JSON."""
    global API_KEY
    if API_KEY:
        io_manager.display_message("Gemini API key found. AI analysis is ON.")
        return
    io_manager.display_message(" \n Gemini API key (get one free at aistudio.google.com/apikey)")
    entered = getpass.getpass(" Paste key (Enter to skip, offline mode)").strip()
    if entered:
        API_KEY = entered
        io_manager.display_message("AI analysis is ON.")
    else:
        io_manager.display_message(" No key entered. Using offline analysis.")

# ──────────────────────────────────────────────
#  MENU
# ──────────────────────────────────────────────


def show_updated_menu() -> int:
    """Show 4-option menu directly here — no touching friend's file!"""
    io_manager.display_header("PHISHGUARD — Main Menu")
    io_manager.display_message("  1. Submit Email Report       (Employee / User)")
    io_manager.display_message("  2. IT Security Personnel    (View & Manage)")
    io_manager.display_message("  3. Keyword Checker Tool")
    io_manager.display_message("  4. Exit")
    return io_manager.prompt_menu_number(4)

def check_it_password() -> bool:
    """Hidden typing, 3 attempts (handled by the I/O Manager)."""
    return io_manager.prompt_it_password(logic_manager.verify_it_password)

# ──────────────────────────────────────────────
#  AI ANALYSIS (Gemini first, offline rules as backup)
# ──────────────────────────────────────────────

def _extract_json(text: str) -> str:
    """Remove a ```json ... ``` fence if the model added one."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        text = text.rsplit("```", 1)[0]
    return text.strip()

def call_gemini_analysis(report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """Try the Gemini API. Returns (result, None) or (None, error message)."""
    if not API_KEY:
        return None, "API key not set"

    if not report.get("viewed", True):
        subject = "NOT VIEWED"
        body = f"Reason: {report.get('reason_for_suspicion', '')}"
    else:
        subject = str(report.get("subject") or "")
        body = str(report.get("body") or "")

    sender = f"{report.get('sender_name', '')} {report.get('sender_email', '')}"

    prompt = f"""Analyze this email for phishing. Return ONLY valid JSON.

SENDER: {sender}
SUBJECT: {subject}
BODY: {body}

Respond with:
{{
  "threat_level": "low|medium|high|critical",
  "confidence": 0.0 to 1.0,
  "impersonation": true or false,
  "urgency_manipulation": true or false,
  "credential_request": true or false,
  "suspicious_link": true or false,
  "attachment_risk": true or false,
  "attack_type": "type or none",
  "recommended_action": "one short sentence",
  "explanation": "Brief reason"
}}"""

    try:
        resp = requests.post(
            API_URL,
            headers={"Content-Type": "application/json", "x-goog-api-key": API_KEY},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.1,
                    "responseMimeType": "application/json",
                },
            },
            timeout=30,
        )
        if resp.status_code != 200:
            return None, f"API Error {resp.status_code}"

        data = resp.json()
        raw = data["candidates"][0]["content"]["parts"][0]["text"]
        result = json.loads(_extract_json(raw))

        if not ai_manager.validate_ai_schema(result):
            return None, "AI reply failed validation"

        result.setdefault("attack_type", "unknown")
        result.setdefault("recommended_action", "")
        result.setdefault("explanation", "")
        result["analysis_mode"] = "Gemini AI"
        return result, None

    except Exception as e:
        return None, f"API error: {e}"


def smart_analyze(report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """Try Gemini first; fall back to the offline rules in ai_manager."""
    result, err = call_gemini_analysis(report)
    if result:
        return result, None

    io_manager.display_message(f"    {err} — using offline analysis")
    result, err = ai_manager.analyze_email(report)
    if result:
        result["analysis_mode"] = "offline rules"
    return result, err

# ──────────────────────────────────────────────
#  HANDLERS
# ──────────────────────────────────────────────


def handle_submit() -> None:
    report = io_manager.collect_report_input()
    io_manager.display_message("\n  Analysing report...")
    ai_result, ai_error = smart_analyze(report)

    records = data_manager.load_records()
    report_id = logic_manager.next_report_id(records)
    record = logic_manager.build_final_record(report_id, report, ai_result, ai_error)

       
    records.append(record)
    data_manager.save_records(records)

    io_manager.display_assessment(record)
    io_manager.display_message("\n  Saved! Status: Pending Review")


def handle_it_panel() -> None:
    if not check_it_password():
        return
    
    while True:
        records = data_manager.load_records()
        io_manager.display_record_list(logic_manager.sort_records_by_priority(records))    
        if not records:
            print("  No reports submitted yet.\n")
            input("Press Enter to return...")
            return
        report_id = io_manager.collect_record_id(records)
        if report_id is None:
            return
        
        idx = logic_manager.find_record_index(records, report_id)
        io_manager.display_record_detail(records[idx])

        updates = io_manager.collect_review_update(
            logic_manager.REVIEW_STATUSES, logic_manager.PRIORITIES)
        if not updates:
            io_manager.display_message("\n  No changes made.")
            continue

        updated, errors = logic_manager.apply_review_update(records[idx], updates)
        if errors:
            for error in errors:
                io_manager.display_error(error)
            continue

        records[idx] = updated
        data_manager.save_records(records)
        io_manager.display_message("\n  Saved.")


def handle_keyword_check():
    text = io_manager.collect_keyword_text()
    if not text:
        io_manager.display_message("  Nothing entered.")
        return
    result = logic_manager.scan_keywords(text)
    io_manager.display_keyword_results(result)



def main():
    try:
        while True:
            choice = show_updated_menu() 
            
            if choice == 1:
                handle_submit()
            elif choice == 2:
                handle_it_panel()
            elif choice == 3:
                handle_keyword_check()
            elif choice == 4:
                io_manager.display_message("\nStay safe! Goodbye.")
                break
            else:
                io_manager.display_message("  Invalid choice — try again.")
    except (EOFError, KeyboardInterrupt):
        io_manager.display_message("\nInput closed. Exiting.")

if __name__ == "__main__":
    main()