# indicator_detector.py under ai_manager.py
# detect what is found in the email and returns the analysis 

import re
from typing import Dict

from config import Config
from email_report import EmailReport

class IndicatorDetector:
    """Runs the detection rules and returns the phishing indicators."""

    def detect(self, report: EmailReport) -> Dict[str, bool]:
        return {
            "impersonation": self._impersonation(report),
            "urgency_manipulation": self._urgency(report),
            "credential_request": self._credential_request(report),
            "suspicious_link": self._suspicious_link(report),
            "attachment_risk": self._attachment_risk(report),
        }
    def _impersonation(self, report: EmailReport) -> bool:
        return bool(
            re.search(r"\b(it support|helpdesk|security team|administrator)\b", report.sender_info)
        ) and bool(
            re.search(r"\b(verify|confirm|unlock|suspend|account|login|password)\b", report.full_text)
        )

    def _urgency(self, report: EmailReport) -> bool:
        return bool(
            re.search(r"\b(urgent|immediately|expir\w*|suspend\w*|deadline)\b", report.full_text)
        )

    def _credential_request(self, report: EmailReport) -> bool:
        return bool(
            re.search(r"\b(password|otp|credentials?|username|log ?in|pin)\b", report.full_text)
        )

    def _suspicious_link(self, report: EmailReport) -> bool:
        joined = " ".join(map(str, report.links)).lower()
        return bool(
            re.search(r"(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|ow\.ly|cutt\.ly)", joined)
        )

    def _attachment_risk(self, report: EmailReport) -> bool:
        return any(
            str(a).lower().endswith(Config.RISKY_ATTACHMENT_EXTENSIONS)
            for a in report.attachments
        )