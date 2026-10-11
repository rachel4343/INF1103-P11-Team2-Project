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