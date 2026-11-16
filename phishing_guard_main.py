# ==============================================
#  PHISHGUARD — Main Program (Fully OOP)
#  INF1103 Phase 2
# ==============================================

import json
import os
import requests
from typing import Dict, Optional, Tuple

# ── Import All Managers (classes only) ────────
from ai_manager import AIManager
from data_manager import DataManager, JsonRecordStore
from io_manager import IOManager, KeywordChecker
from logic_manager import (
    LogicManager,
    REVIEW_STATUSES,
    PRIORITIES,
    THREAT_LEVELS,
)

# ── Configuration ─────────────────────────────
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent"
API_KEY = os.environ.get("GEMINI_API_KEY", "")
DATA_FILE = "phishguard_reports.json"


class GeminiAPIClient:
    """Handles communication with Google Gemini API — isolated component."""

    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key
        self.enabled = bool(api_key)

    @staticmethod
    def _extract_json(text: str) -> str:
        """Remove markdown code fence if present."""
        text = text.strip()
        if text.startswith("```"):
            if "\n" in text:
                text = text.split("\n", 1)[1]
            text = text.rsplit("```", 1)[0]
        return text.strip()

    def build_prompt(self, report: Dict) -> str:
        """Construct the analysis prompt from report data."""
        if not report.get("viewed", True):
            subject = "NOT VIEWED"
            body = f"Reason: {report.get('reason_for_suspicion', '')}"
        else:
            subject = str(report.get("subject") or "")
            body = str(report.get("body") or "")

        sender = f"{report.get('sender_name', '')} {report.get('sender_email', '')}"

        return f"""Analyze this email for phishing. Return ONLY valid JSON.

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

    def analyze(self, report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
        """Call API — returns (result_dict, None) or (None, error_message)."""
        if not self.enabled:
            return None, "API key not set"

        prompt = self.build_prompt(report)

        try:
            resp = requests.post(
                self.api_url,
                headers={
                    "Content-Type": "application/json",
                    "x-goog-api-key": self.api_key
                },
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
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            result = json.loads(self._extract_json(raw_text))

            # Normalize fields
            result.setdefault("attack_type", "unknown")
            result.setdefault("recommended_action", "")
            result.setdefault("explanation", "")
            result["analysis_mode"] = "Gemini AI"
            return result, None

        except Exception as e:
            return None, f"API error: {str(e)}"


class AnalysisOrchestrator:
    """Orchestrates AI analysis — tries Gemini first, falls back to offline rules.

    The IOManager is optional so the web interface can use this class
    without printing to the console.
    """

    def __init__(self, gemini_client: GeminiAPIClient, ai_manager: AIManager,
                 io: Optional[IOManager] = None):
        self.gemini = gemini_client
        self.ai_mgr = ai_manager
        self.io = io

    def analyze(self, report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
        """Dual-path analysis: cloud → local fallback."""
        result, err = self.gemini.analyze(report)
        if result:
            return result, None

        if self.io is not None:
            self.io.display_message(f"    {err} — using offline analysis")
        result, err = self.ai_mgr.analyze_email(report)
        if result:
            result["analysis_mode"] = "offline rules"
        return result, err


class ITSecurityPanel:
    """Handles IT login, review workflow and report management."""

    def __init__(self, data_mgr: DataManager, logic_mgr: LogicManager, io: IOManager):
        self.data_mgr = data_mgr
        self.logic_mgr = logic_mgr
        self.io = io

    def authenticate(self) -> bool:
        """Verify IT personnel credentials (hashed password, 3 attempts)."""
        if self.io.prompt_it_password(self.logic_mgr.verify_it_password):
            self.io.display_message("  Login successful!\n")
            return True
        return False

    def _review_single_report(self, records: list, idx: int) -> bool:
        """Process one report review — returns True if saved."""
        self.io.display_record_detail(records[idx])

        if records[idx].get("review_stage") == "closed":
            self.io.display_message("  This report is finalised — no changes allowed.")
            return False

        updates = self.io.collect_review_update(records[idx])
        updated, errors = self.logic_mgr.apply_review_update(records[idx], updates)

        if errors:
            for err in errors:
                self.io.display_error(err)
            return False

        records[idx] = updated
        if not self.data_mgr.save_records(records):
            for warning in self.data_mgr.take_warnings():
                self.io.display_error(warning)
            self.io.display_error("Review could not be saved.")
            return False

        # Status feedback
        stage = updated.get("review_stage")
        if stage == "awaiting_second_review":
            self.io.display_message(f" First review saved — waiting for {updated.get('assigned_reviewer')}")
        elif stage == "closed":
            self.io.display_message("  Finalised & Locked — no further changes.")
        else:
            self.io.display_message("  Sent back for reassessment.")
        return True

    def _open_results(self, records: list, found: list):
        """Handle search results — single or multiple matches."""
        if not found:
            self.io.display_error("No reports match that.")
            return
        if len(found) == 1:
            report_id = found[0].get("report_id", "")
        else:
            self.io.display_record_list(found)
            report_id = self.io.collect_record_id(found)
            if report_id is None:
                return

        idx = self.logic_mgr.find_record_index(records, report_id)
        if idx < 0:
            self.io.display_error("Report no longer available.")
            return
        self._review_single_report(records, idx)

    def search_workflow(self):
        """Search & filter reports then review."""
        records = self.data_mgr.load_records()
        if not records:
            self.io.display_message("  No reports submitted yet.")
            self.io.pause("  Press Enter to return...")
            return

        choice = self.io.prompt_choice(
            "\nFind a report:",
            [
                "Find by ID or keywords",
                "Filter by priority",
                "Filter by threat level",
                "Filter by review status",
                "Filter by risk score",
                "Back"
            ],
        )

        if choice == "Back":
            return
        elif choice == "Find by ID or keywords":
            text = self.io.prompt_text("Report ID, sender, subject or words")
            exact = self.data_mgr.find_record(records, text)
            found = [exact] if exact else self.data_mgr.search_records(records, text)
        elif choice == "Filter by priority":
            val = self.io.prompt_choice("Priority:", list(PRIORITIES))
            found = self.data_mgr.filter_records(records, priority=val)
        elif choice == "Filter by threat level":
            val = self.io.prompt_choice("Threat level:", list(THREAT_LEVELS) + ["unknown"])
            found = self.data_mgr.filter_records(records, threat_level=val)
        elif choice == "Filter by review status":
            val = self.io.prompt_choice("Review status:", list(REVIEW_STATUSES))
            found = self.data_mgr.filter_records(records, review_status=val)
        else:
            low = self.io.prompt_text("Lowest risk (Enter = 0)", required=False,
                                      validator=str.isdigit) or "0"
            high = self.io.prompt_text("Highest risk (Enter = 100)", required=False,
                                       validator=str.isdigit) or "100"
            found = self.data_mgr.filter_records(
                records, min_risk=int(low), max_risk=int(high)
            )

        self._open_results(records, found)

    def main_menu(self):
        """IT panel loop — shown after login."""
        while True:
            records = self.data_mgr.load_records()
            self.io.display_record_list(self.logic_mgr.sort_records_by_priority(records))

            if not records:
                self.io.display_message("  No reports submitted yet.\n")
                self.io.pause("  Press Enter to return...")
                return

            report_id = self.io.collect_record_id(records)
            if report_id is None:
                return

            idx = self.logic_mgr.find_record_index(records, report_id)
            if idx < 0:
                self.io.display_error("Report not found.")
                continue

            self._review_single_report(records, idx)


class KeywordCheckerPanel:
    """Keyword checker tool: offline quick scan or AI deep scan."""

    def __init__(self, io: IOManager, checker: KeywordChecker,
                 analyzer: AnalysisOrchestrator):
        self.io = io
        self.checker = checker
        self.analyzer = analyzer

    def quick_scan(self):
        """Offline keyword scan — instant, no internet needed."""
        self.io.display_header("Keyword Checker — Quick Scan")
        text = self.io.collect_keyword_text()
        sender = self.io.prompt_text("Sender name (optional)", required=False)
        self.io.display_keyword_results(self.checker.scan(text, sender))

    def deep_scan(self):
        """AI deep scan — uses Gemini, falls back to offline rules."""
        self.io.display_header("Keyword Checker — Deep Scan")
        text = self.io.collect_keyword_text()
        sender = self.io.prompt_text("Sender name (optional)", required=False)
        report = {
            "subject": "",
            "body": text,
            "sender_name": sender,
            "sender_email": "",
            "viewed": True,
        }
        self.io.display_message("\n  Analysing...")
        result, err = self.analyzer.analyze(report)
        if result:
            self.io.display_ai_keyword_results(result)
        else:
            self.io.display_error(f"Deep scan failed: {err}")

    def menu(self):
        """Sub-menu loop."""
        while True:
            self.io.display_header("KEYWORD CHECKER — Select Scan Type")
            self.io.display_message("  1. Quick Scan — Offline, instant, no internet needed")
            self.io.display_message("  2. Deep Scan  — AI-powered, understands context & meaning")
            self.io.display_message("  3. Back to Main Menu")

            choice = self.io.prompt_menu_number(3)
            if choice == 1:
                self.quick_scan()
            elif choice == 2:
                self.deep_scan()
            else:
                self.io.display_message("  Returning to Main Menu...")
                break


class PhishGuardApp:
    """Main Application — coordinates all subsystems."""

    def __init__(self):
        # One IOManager object is shared by every class that talks to the user
        self.io = IOManager()
        self.store = JsonRecordStore(DATA_FILE)
        self.data_mgr = DataManager(self.store)
        self.logic_mgr = LogicManager()
        self.ai_mgr = AIManager()
        self.gemini = GeminiAPIClient(API_URL, API_KEY)
        self.analyzer = AnalysisOrchestrator(self.gemini, self.ai_mgr, self.io)
        self.it_panel = ITSecurityPanel(self.data_mgr, self.logic_mgr, self.io)
        self.keyword_panel = KeywordCheckerPanel(self.io, KeywordChecker(), self.analyzer)

    def show_startup_message(self):
        """Display API status at launch."""
        if self.gemini.enabled:
            self.io.display_message("  Gemini API analysis — ON")
        else:
            self.io.display_message("   No API key — using offline analysis only")
            self.io.display_message("   Set: $env:GEMINI_API_KEY='your-key'")

    def _show_main_menu(self) -> int:
        """Display main menu & get selection."""
        self.io.display_header("PHISHGUARD — Main Menu")
        self.io.display_message("  1. Submit Email Report (Employee / User)")
        self.io.display_message("  2. IT Security Personnel (Review & Manage)")
        self.io.display_message("  3. Keyword Checker Tool")
        self.io.display_message("  4. Find a Report (Search & Filter)")
        self.io.display_message("  5. Exit")
        return self.io.prompt_menu_number(5)

    def _submit_report(self):
        """Handle new report submission flow."""
        report = self.io.collect_report()
        self.io.display_message("\n  Analysing report...")

        ai_result, ai_error = self.analyzer.analyze(report)
        records = self.data_mgr.load_records()
        report_id = self.logic_mgr.next_report_id(records)
        record = self.logic_mgr.build_final_record(report_id, report, ai_result, ai_error)

        outcome = self.data_mgr.add_record(record)

        for warning in self.data_mgr.take_warnings():
            self.io.display_message(f"   {warning}")

        if outcome.get("duplicate"):
            self.io.display_message("   Duplicate — already saved.")
            return
        if not outcome.get("saved"):
            self.io.display_error("  Failed to save report.")
            return

        if outcome.get("same_scam_before", 0) > 0:
            self.io.display_message(
                f"   Similar scam reported {outcome['same_scam_before']} time(s) before.")

        self.io.display_assessment(record)
        self.io.display_message(f"\n  Saved! Report ID: {report_id}")

    def run(self):
        """Application main loop."""
        self.io.display_message("=" * 55)
        self.io.display_message("  PHISHGUARD — AI-Powered Phishing Detector")
        self.io.display_message("         INF1103 Phase 2 — OOP Refactored")
        self.io.display_message("=" * 55)

        self.show_startup_message()

        while True:
            choice = self._show_main_menu()

            if choice == 1:
                self._submit_report()
            elif choice == 2:
                if self.it_panel.authenticate():
                    self.it_panel.main_menu()
            elif choice == 3:
                self.keyword_panel.menu()
            elif choice == 4:
                if self.it_panel.authenticate():
                    self.it_panel.search_workflow()
            elif choice == 5:
                self.io.display_message("\n  Thank you for using PhishGuard! Stay safe.")
                break


# ── ENTRY POINT ───────────────────────────────
if __name__ == "__main__":
    try:
        PhishGuardApp().run()
    except (EOFError, KeyboardInterrupt):
        print("\n\n  Exiting PhishGuard. Goodbye!")