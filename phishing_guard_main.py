import re
import io_manager
import data_manager
import ai_manager
import logic_manager
import requests
import json
from typing import Dict, Optional, Tuple


API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"
API_KEY = "AIzaSyD-Your-API-Key-Here"

def call_gemini_analysis(report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """Try Gemini API first; return (None, error) if fails."""
    
    if "paste_your_key" in API_KEY:
        return None, "API key not set"
    
    # Prepare text from report
    viewed = report.get("viewed", True)
    if not viewed:
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
  "explanation": "Brief reason"
}}"""

    try:
        resp = requests.post(
            f"{API_URL}?key={API_KEY}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.1}
            },
            timeout=60
        )
        
        if resp.status_code != 200:
            return None, f"API Error {resp.status_code}"
        
        data = resp.json()
        result_text = data["candidates"][0]["content"]["parts"][0]["text"].strip("` \n")
        result = json.loads(result_text)
        result["analysis_mode"] = "Gemini AI"
        return result, None
        
    except Exception as e:
        return None, f"API error: {str(e)}"  

def smart_analyze(report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """Try Gemini first; auto-switch to ai_manager if anything fails."""
    
    
    result, err = call_gemini_analysis(report)
    if result:
        return result, None  
    
    
    print(f"    {err} — using offline analysis")
    result = ai_manager.analyze_email(report)
    if result[0]:
        result[0]["analysis_mode"] = "offline rules"
    return result

def handle_submit(records):
    report = io_manager.collect_report_input()
    io_manager.display_message("\n  Analysing report...")
    
    # Use smart analysis — Gemini or fallback
    ai_result, ai_error = smart_analyze(report)
    
    report_id = logic_manager.next_report_id(records)
    record = logic_manager.build_final_record(report_id, report, ai_result, ai_error)
    records.append(record)
    data_manager.save_report(report, records)
    io_manager.display_assessment(records)
    io_manager.display_message(f"\n  Saved. Total reports: {len(records)}")

def handle_it_panel(records):
    io_manager.display_header("IT SECURITY — REPORT REVIEW")
    if not records:
        io_manager.display_message("  No reports submitted yet.")
    else:
        sorted_records = logic_manager.sort_records_by_priority(records)
        io_manager.display_record_list(sorted_records)
    input("\nPress Enter to return to Main Menu...")

def handle_keyword_check():
    text = io_manager.collect_keyword_text()
    if not text:
        io_manager.display_message("  Nothing entered.")
        return
    result = logic_manager.scan_keywords(text)
    io_manager.display_keyword_results(result)

def main():
    records = data_manager._load()
    try:
        while True:
            choice = io_manager.show_main_menu()
            if choice == 1:
                handle_submit(records)
            elif choice == 2:
                handle_it_panel(records)
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