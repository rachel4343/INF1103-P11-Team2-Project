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
