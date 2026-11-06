## privacy_filter.py under io_manager.py
"""PhishGuard I/O: PrivacyFilter definition."""
from __future__ import annotations

import re
from typing import Dict

class PrivacyFilter:
    """Mask common personal identifiers in ALL free-text and extracted fields."""
    # NRIC/FIN: optional space or hyphen between letter, digits and checksum.
    _nric = re.compile(r"\b([STFGMstfgm])[\s-]?\d{7}[\s-]?([A-Za-z])\b")
    # SG mobile/landline: 8 digits starting 6/8/9, optional +65/65 prefix,
    # optional space or hyphen in the middle (9123 4567, +65 9123-4567).
    _phone = re.compile(r"(?<!\d)(\+?65[\s-]?)?([689]\d)\d{2}[\s-]?\d{2}(\d{2})(?!\d)")
    _email = re.compile(r"([\w.+-])[\w.+-]*@([\w-]+(?:\.[\w-]+)+)")

    def blur(self, text: str) -> str:
        text = str(text or "")
        text = self._nric.sub(r"\1*******\2", text)
        text = self._phone.sub(lambda m: f"{m.group(1) or ''}{m.group(2)}****{m.group(3)}", text)
        return self._email.sub(r"\1***@\2", text)

    def sanitise_fields(self, data: Dict) -> Dict:
        """Keep sender_email for phishing analysis (as in Phase 1)."""
        result = dict(data)
        for key in ("sender_name", "subject", "body", "reason_for_suspicion"):
            result[key] = self.blur(str(result.get(key) or ""))
        result["urls"] = [self.blur(str(url)) for url in result.get("urls", [])]
        return result

