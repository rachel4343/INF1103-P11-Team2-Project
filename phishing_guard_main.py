import os
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
DATA_FILE = "phishguard_reports.json"


def show_updated_menu() -> int:
    """Show 4-option menu directly here — no touching friend's file!"""
    io_manager.display_header("PHISHGUARD — Main Menu")
    io_manager.display_message("  1. Submit Email Report       (Employee / User)")
    io_manager.display_message("  2. IT Security Personnel    (View & Manage)")
    io_manager.display_message("  3. Keyword Checker Tool")
    io_manager.display_message("  4. Exit")
    while True:
        raw = input("\nChoose (1-4): ").strip()
        if raw in ("1", "2", "3", "4"):
            return int(raw)
        io_manager.display_error("Please choose 1, 2, 3, or 4.")

def check_it_password() -> bool:
    print("\n" + "=" * 55)
    print("        IT SECURITY — LOGIN REQUIRED")
    print("=" * 55)
    entered = input("  Enter password: ").strip()
    
    if logic_manager.verify_it_password(entered):
        print("  Access granted! Welcome, Security Team.\n")
        return True
    else:
        print("  Incorrect password. Access denied.")
        input("\nPress Enter to return to Main Menu...")
        return False

def call_gemini_analysis(report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    prompt = f"""Analyze this email..."""
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

def handle_submit():
    report = io_manager.collect_report_input()
    io_manager.display_message("\n  Analysing report...")
    ai_result, ai_error = smart_analyze(report)
    
    records = load_all_records()
    report_id = logic_manager.next_report_id(records)
    record = logic_manager.build_final_record(report_id, report, ai_result, ai_error)
    
    # Default values for IT to fill
    record["status"] = "Pending Review"
    record["priority_override"] = None
    record["investigation_notes"] = ""
    record["assigned_reviewer"] = ""
    
    save_all_records(records + [record])
    
    io_manager.display_assessment(record)
    io_manager.display_message(f"\n  Saved! Status: Pending Review")

def handle_it_panel():
    if not check_it_password():
        return
    
    while True:
        io_manager.display_header("IT SECURITY — REPORT REVIEW")
        records = load_all_records()
        
        if not records:
            print("  No reports submitted yet.\n")
            input("Press Enter to return...")
            return
        
        # Show summary list
        print(f"  {'ID':<5} {'Threat Level':<15} {'Status':<18} {'Assignee':<15}")
        print("  " + "-" * 65)
        for rec in records:
            level = rec.get("threat_level", "unknown").upper()
            status = rec.get("status", "Pending Review")
            assignee = rec.get("assigned_reviewer", "(unassigned)")
            print(f"  #{rec['report_id']:<3} {level:<15} {status:<18} {assignee:<15}")
        
        print("\n  Enter ID to update → 'q' to go back")
        choice = input("  Your choice: ").strip()
        
        if choice.lower() == "q":
            break
        
        # Find report
        found = None
        for rec in records:
            if str(rec["report_id"]) == choice:
                found = rec
                break
        
        if not found:
            print(f"\n   Report #{choice} not found.")
            input("Press Enter to continue...")
            continue
        
        # Show full details
        print("\n" + "=" * 65)
        print(f"  REPORT #{found['report_id']} — FULL DETAILS")
        print("=" * 65)
        print(f"  Threat Level:     {found.get('threat_level', 'N/A')}")
        print(f"  Current Status:   {found.get('status', 'Pending Review')}")
        print(f"  Priority Override:{found.get('priority_override', '(system default)')}")
        print(f"  Assigned Reviewer:{found.get('assigned_reviewer', '(unassigned)')}")
        print(f"  Investigation Notes:")
        note = found.get("investigation_notes", "")
        print(f"    {note if note else '(no notes yet)'}")
        print("=" * 65)
        print("  UPDATE OPTIONS:")
        print("  1. Update Report Status")
        print("  2. Override Priority Level")
        print("  3. Add/Edit Investigation Notes")
        print("  4. Assign Reviewer")
        print("  5. Save & Return to List")
        
        while True:
            action = input("\n  Choose action (1-5): ").strip()
            
            if action == "1":
                print("\n  Status options: Pending Review · In Progress · Approved / Handled · Dismissed")
                new_status = input("  Enter new status: ").strip()
                found["status"] = new_status
                print(f"   Status updated to: {new_status}")
            
            elif action == "2":
                print("\n  Priority options: low · medium · high · critical")
                new_prio = input("  Enter overridden priority: ").strip()
                found["priority_override"] = new_prio
                print(f"   Priority set to: {new_prio}")
            
            elif action == "3":
                print("\n  Enter your findings / actions taken:")
                new_note = input("  Notes: ").strip()
                found["investigation_notes"] = new_note
                print("   Notes saved")
            
            elif action == "4":
                name = input("\n  Enter reviewer name: ").strip()
                found["assigned_reviewer"] = name
                print(f"   Assigned to: {name}")
            
            elif action == "5":
                # Save everything to JSON file
                idx = records.index(found)
                records[idx] = found
                save_all_records(records)
                print("\n  All changes saved to file!")
                break
            
            else:
                print("   Invalid choice — try again")
        
        input("\nPress Enter to continue...")

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