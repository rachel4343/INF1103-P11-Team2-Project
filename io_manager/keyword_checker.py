## keyword_checker.py under io_manager.py
"""PhishGuard I/O: KeywordChecker definition."""
from __future__ import annotations

import re
from typing import Dict, List

class KeywordChecker:
    """Optional employee keyword tool. Produces the original Phase 1 schema.

    The Logic Manager should remain responsible for final risk/priority decisions.
    """
    WORDS = {
        "urgency": ["urgent", "immediately", "now", "expire", "deadline", "suspend", "block", "close", "act fast", "right now", "limited time"],
        "credential": ["password", "login", "verify", "account", "otp", "pin", "username", "sign in", "confirm", "credential"],
        "impersonation": ["it support", "helpdesk", "security team", "hr department", "admin", "system admin", "technical team", "it department"],
        "risky_links": ["bit.ly", "tinyurl", "goo.gl", "login-verify", "account-verify"],
    }
    POINTS = {"urgency": 1, "credential": 2, "impersonation": 2, "risky_links": 2}
    LEVELS = ((6, "critical"), (4, "high"), (2, "medium"), (1, "low"))

    @staticmethod
    def _find(words: List[str], haystack: str) -> List[str]:
        return [w for w in words if re.search(
            r"(?<![a-z0-9])" + re.escape(w) + r"(?:s|es|ed|d)?(?![a-z0-9])", haystack)]

    def scan(self, text: str, sender: str = "") -> Dict:
        text, sender = (text or "").lower(), (sender or "").lower()
        found = {k: self._find(v, sender if k == "impersonation" else text)
                 for k, v in self.WORDS.items()}
        if not found["credential"]:
            found["impersonation"] = []
        score = sum(self.POINTS[k] * len(v) for k, v in found.items())
        level = next((name for minimum, name in self.LEVELS if score >= minimum), "safe")
        return {"found": found, "score": score, "level": level}

