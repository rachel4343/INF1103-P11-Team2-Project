## email_text_parser.py under io_manager.py
"""Parse locally extracted email screenshot text into report fields."""
from __future__ import annotations

import re
from typing import Dict
from .io_helpers import clean
from .input_validator import InputValidator
from .extraction_error import ExtractionError

class EmailTextParser:
    """Convert raw OCR text into the same fields as typed submission."""
    EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    FROM = re.compile(r"^\s*(?:from|sender)\s*:\s*(.+)$", re.I)
    SUBJECT = re.compile(r"^\s*subject\s*:\s*(.+)$", re.I)
    URL = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)

    def parse(self, source: str) -> Dict:
        text = clean(source or "")
        if len(text) < 8:
            raise ExtractionError("too little readable text in the screenshot")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        sender_line, sender_index = "", None
        for index, line in enumerate(lines):
            match = self.FROM.match(line)
            if match:
                sender_line, sender_index = match.group(1), index
                break
        if sender_index is None:
            for index, line in enumerate(lines[:12]):
                if self.EMAIL.search(line):
                    sender_line, sender_index = line, index
                    break
        match = self.EMAIL.search(sender_line)
        email = match.group(0) if match else ""
        name = re.sub(r"^\s*(?:from|sender)\s*:\s*", "", sender_line, flags=re.I)
        name = name.replace(email, "").strip(" <>\"'()[]:,")
        if name.lower() in ("to me", "me", "to:", "reply", "forward"):
            name = ""
        subject = next((m.group(1).strip() for line in lines
                        if (m := self.SUBJECT.match(line))), "")
        if not subject and sender_index is not None and sender_index > 0:
            previous = lines[sender_index - 1]
            if not self.EMAIL.search(previous):
                subject = previous
        urls = []
        for url in self.URL.findall(text):
            url = url.rstrip(".,;:!?)\"']")
            if InputValidator.url(url) and url not in urls:
                urls.append(url)
        return {"sender_email": email, "sender_name": name, "subject": subject,
                "body": text, "urls": urls}

