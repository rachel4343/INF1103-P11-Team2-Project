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
        # If OCR could not extract a valid address, don't treat the broken
        # address (for example, johnson@ss&s.com) as a display name.
        # The I/O Manager will ask the user to correct the sender email.
        if not email and "@" in sender_line:
            name = ""
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

    # New feature: validate OCR *text structure* before using an image as an email.
    # This deliberately remains in EmailTextParser rather than adding a new class/file.
    TO_HEADER = re.compile(r"^\s*(?:to|cc|bcc)\s*:\s*\S", re.I)
    MAIL_CONTROLS = re.compile(r"\b(?:reply\s*all|replyall|reply|forward|inbox)\b", re.I)
    HEADER_LINES = 12
    MIN_MESSAGE_CHARS = 24

    def validate_email_screenshot(self, source: str, fields: Dict) -> None:
        """Reject OCR output without convincing email structure and message text.

        This checks recognised TEXT, not image authenticity. A disguised text image
        can still pass; a heavily cropped/unusual email may fail. Keep manual fallback.
        """
        text = clean(source or "")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) < 3 or len(text) < 50:
            raise ExtractionError(
                "Image has too little readable email information. "
                "Capture the sender, subject and message together."
            )

        header = lines[:self.HEADER_LINES]
        # Prefer an explicitly labelled From: field. OCR may read a name or
        # unusual/partially corrupted address without matching EMAIL exactly.
        from_lines = [
            (i, match.group(1).strip())
            for i, line in enumerate(header)
            if (match := self.FROM.match(line)) and match.group(1).strip()
        ]
        labelled_sender = bool(from_lines)
        sender_indices = [i for i, line in enumerate(header) if self.EMAIL.search(line)]
        if from_lines:
            sender_index = from_lines[0][0]
        elif sender_indices:
            sender_index = sender_indices[0]
        else:
            raise ExtractionError(
                "Image does not look like an email screenshot: "
                "no sender information was found near the top."
            )
        subject_indices = [
            i for i, line in enumerate(header) if self.SUBJECT.match(line)
        ]
        has_recipient = any(self.TO_HEADER.match(line) for line in header)
        has_mail_toolbar = any(self.MAIL_CONTROLS.search(line) for line in header)

        # Webmail UIs often display an unlabelled subject directly above the sender.
        possible_subject_title = (
            sender_index > 0
            and any(
                8 <= len(line) <= 220
                and not self.EMAIL.search(line)
                and not self.TO_HEADER.match(line)
                and not re.match(r"^\s*(?:date|time)\s*:", line, re.I)
                and line.lower() not in {"inbox", "reply", "forward", "reply all"}
                for line in header[max(0, sender_index - 2):sender_index]
            )
        )
        # Full From/Subject headers are evidence of an email screenshot,
        # even if the actual address was misread (e.g. ss&s.com). To avoid
        # accepting an unrelated document with two labelled lines, require
        # a recipient, an email-like address, or a mail-client control too.
        from_value = from_lines[0][1] if from_lines else ""
        sender_looks_like_address = bool(re.search(r"\S+@\S+\.\S+", from_value))
        has_email_headers = (
            labelled_sender
            and bool(subject_indices)
            and (sender_looks_like_address or has_recipient or has_mail_toolbar)
        )
        looks_like_email_client = (
            bool(sender_indices)
            and (has_recipient or has_mail_toolbar)
            and (bool(subject_indices) or possible_subject_title)
        )
        if not (has_email_headers or looks_like_email_client):
            raise ExtractionError(
                "Image does not look like an email screenshot. "
                "Expected From/Subject headers or an email-client view "
                "with sender, subject and To/Reply controls."
            )

        # Rule out an image that only contains email headers and no message.
        body_start = max([sender_index, *subject_indices]) + 1
        message_lines = [
            line for line in lines[body_start:]
            if not self.TO_HEADER.match(line)
            and not self.FROM.match(line)
            and not self.SUBJECT.match(line)
            and not self.MAIL_CONTROLS.fullmatch(line)
        ]
        if len(" ".join(message_lines).strip()) < self.MIN_MESSAGE_CHARS:
            raise ExtractionError(
                "Email headers were found, but the screenshot has too little "
                "message text. Include the email body in the screenshot."
            )

        # A bad OCR address is a FIELD correction problem, not proof that
        # the picture isn't an email. IOManager._screenshot() already prompts
        # the user to enter a valid sender email if this field is missing.
        email = str(fields.get("sender_email") or "")
        if not self.EMAIL.fullmatch(email) and not has_email_headers:
            raise ExtractionError(
                "The sender email could not be read clearly. "
                "Please use a clearer email screenshot."
            )
