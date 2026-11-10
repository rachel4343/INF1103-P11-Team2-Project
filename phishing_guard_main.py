# ==============================================
#  PHISHGUARD — Main Program (OOP Refactored)
#  INF1103 Phase 2
# ==============================================

import getpass
import json
import os
import requests
from typing import Dict, Optional, Tuple

# ── Import All Managers ───────────────────────
from ai_manager import AIManager
from data_manager import DataManager, JsonRecordStore
from io_manager import (
    display_header,
    display_message,
    display_error,
    display_assessment,
    display_record_list,
    display_record_detail,
    display_keyword_results,
    prompt_menu_number,
    prompt_choice,
    prompt_text,
    collect_report_input,
    collect_review_update,
    collect_record_id,
    collect_keyword_text,
    prompt_it_password,
)
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