"""PhishGuard I/O Manager: employee reporting, OCR workflow, IT review input/output.

This module defines only IOManager. Supporting classes live in io_components/.
Legacy imports are re-exported below to keep existing team scripts/tests working.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Sequence, Tuple
from .io_config import (MAX_FIELD_LENGTH, MAX_BODY_LENGTH, MAX_URL_LENGTH,
                                     BODY_END_MARKER, LINE_WIDTH, MAX_NOTE, MAX_NAME,
                                     MAX_IMAGE, MAX_FILE, INDICATORS)
from .io_helpers import clean, short
from .privacy_filter import PrivacyFilter
from .io_channel import IOChannel
from .console_channel import ConsoleChannel
from .scripted_channel import ScriptedChannel
from .input_validator import InputValidator
from .extraction_error import ExtractionError
from .email_extractor import EmailExtractor
from .keyword_checker import KeywordChecker
from .attachment_reader import AttachmentReader
from .menu_choice import MenuChoice

class IOManager:
    """The single I/O entry point for main.py; all report fields stay compatible."""
    METHODS = ("Type the email details", "Read email screenshot locally (OCR)")

    def __init__(self, channel: Optional[IOChannel] = None,
                 extractor: Optional[EmailExtractor] = None,
                 evidence_store=None, keyword_checker: Optional[KeywordChecker] = None):
        self._channel = channel or ConsoleChannel()
        self._privacy = PrivacyFilter()
        self._files = AttachmentReader()
        self._keywords = keyword_checker or KeywordChecker()
        self._evidence_store = evidence_store
        if extractor is None:
            from ocr_extractor import TesseractExtractor
            extractor = TesseractExtractor()
        # Privacy-first: do not accept remote/vision extractors in screenshot flow.
        # No image bytes are sent to Gemini from the I/O layer.
        if not getattr(extractor, "local_only", False):
            raise ValueError("I/O screenshot extractor must run locally; use TesseractExtractor")
        self._extractor = extractor

    def display_message(self, text: str = "") -> None:
        self._channel.write(str(text))

    def display_error(self, text: str) -> None:
        self.display_message(f"  [!] {text}")

    def display_header(self, title: str) -> None:
        self.display_message("\n" + "=" * LINE_WIDTH)
        self.display_message(f"  {title}")
        self.display_message("=" * LINE_WIDTH)

    def _read(self, label: str, required=True, maximum=MAX_FIELD_LENGTH,
              validator: Optional[Callable[[str], bool]] = None) -> str:
        while True:
            value = clean(self._channel.read(f"{label}: "))
            if not value:
                if required:
                    self.display_error("This field is required.")
                    continue
                return ""
            if len(value) > maximum:
                self.display_error(f"Too long (max {maximum} characters).")
                continue
            if validator and not validator(value):
                self.display_error("Invalid format; please try again.")
                continue
            return value

    def _yes_no(self, label: str) -> bool:
        while True:
            value = self._channel.read(f"{label} (yes/no): ").strip().lower()
            if value in ("yes", "y"):
                return True
            if value in ("no", "n"):
                return False
            self.display_error("Please answer yes or no.")

    def _choose(self, label: str, options: Sequence[str], allow_skip=False) -> Optional[str]:
        self.display_message(label)
        for number, option in enumerate(options, 1):
            self.display_message(f"  {number}. {option}")
        while True:
            raw = self._channel.read(f"Choose 1-{len(options)}: ").strip()
            if allow_skip and not raw:
                return None
            if raw.isdecimal() and 1 <= int(raw) <= len(options):
                return options[int(raw) - 1]
            self.display_error("Please enter a valid menu number.")

    def _multiline(self, label: str) -> str:
        while True:
            self.display_message(f"{label} (type {BODY_END_MARKER} on its own line to finish):")
            lines = []
            while True:
                line = self._channel.read("")
                if line.strip().upper() == BODY_END_MARKER.upper():
                    break
                lines.append(line)
            value = clean("\n".join(lines))
            if 0 < len(value) <= MAX_BODY_LENGTH:
                return value
            self.display_error(f"Text is required, maximum {MAX_BODY_LENGTH} characters.")

    def _urls(self) -> List[str]:
        while True:
            raw = self._read("URLs found (comma-separated, Enter if none)", required=False,
                             maximum=MAX_BODY_LENGTH)
            urls = [v.strip() for v in raw.split(",") if v.strip()]
            if all(InputValidator.url(v) for v in urls):
                return urls
            self.display_error("Invalid URL; please try again.")

    def show_main_menu(self) -> MenuChoice:
        self.display_header("PHISHGUARD — Main Menu")
        labels = ("Submit Email Report (Employee / User)",
                  "IT Security Personnel (View & Manage)",
                  "Keyword Checker Tool", "Exit")
        choice = self._choose("", labels)
        return MenuChoice(labels.index(choice) + 1)

    def prompt_it_password(self, verify: Callable[[str], bool]) -> bool:
        self.display_message("\nIT / Cybersecurity access requires a password.")
        for attempt in range(3):
            if verify(self._channel.read_secret("Password: ")):
                return True
            remaining = 2 - attempt
            self.display_error(f"Incorrect password. {remaining} attempt(s) left." if remaining
                               else "Too many attempts. Returning to main menu.")
        return False

    def _typed(self) -> Dict:
        self.display_message("\nEnter the email details.")
        return {"sender_email": self._read("Sender email", validator=InputValidator.email),
                "sender_name": self._read("Sender display name", required=False),
                "subject": self._read("Email subject"),
                "body": self._multiline("Email message"), "urls": self._urls()}

    def _screenshot(self) -> Optional[Tuple[Dict, Dict]]:
        """OCR stays local; raw OCR string is sanitised before any preview/return."""
        self.display_message("\nThe screenshot is read locally and is NOT uploaded or saved.")
        self.display_message("Only the masked text and a file hash go into the report.")
        if not self._extractor.is_available():
            self.display_error("Local Tesseract OCR is unavailable. Switching to typing.")
            return None
        while True:
            path = self._read("Screenshot file path (Enter to cancel)", required=False, maximum=500)
            if not path:
                return None
            try:
                image = self._files.inspect(path, image_only=True)
                raw = self._extractor.extract(image["path"])
                break
            except (ValueError, ExtractionError) as exc:
                self.display_error(f"Could not read screenshot: {exc}")
                if not self._yes_no("Try another screenshot?"):
                    return None
        # Immediately mask OCR text, including all URLs, before displaying it.
        fields = self._privacy.sanitise_fields({
            "sender_email": str(raw.get("sender_email") or ""),
            "sender_name": str(raw.get("sender_name") or "")[:MAX_FIELD_LENGTH],
            "subject": str(raw.get("subject") or "")[:MAX_FIELD_LENGTH],
            # Mask the complete OCR output before displaying or limiting its length.
            "body": str(raw.get("body") or ""),
            "urls": [u for u in raw.get("urls", []) if isinstance(u, str) and InputValidator.url(u)],
        })
        if not InputValidator.email(fields["sender_email"]):
            fields["sender_email"] = ""
        self.display_message("\nExtracted information (sensitive text masked):")
        for key in ("sender_email", "sender_name", "subject"):
            self.display_message(f"  {key}: {fields[key] or '(not found)'}")
        self.display_message("  URLs: " + (", ".join(fields["urls"]) or "none"))
        self.display_message("  Email text (complete masked OCR preview):")
        if fields["body"]:
            # Show every line in full, including lines past the old 10-line limit.
            for line in fields["body"].splitlines():
                self.display_message("    " + line)
        else:
            self.display_message("    (no readable message text)")
        if len(fields["body"]) > MAX_BODY_LENGTH:
            self.display_error(
                f"OCR text contains {len(fields['body'])} characters. "
                f"Only the first {MAX_BODY_LENGTH} can be saved as the report body. "
                "Choose 'no' below to edit the message if needed."
            )
            fields["body"] = fields["body"][:MAX_BODY_LENGTH]
        if not (self._yes_no("Is the extracted information correct?")
                and all(fields[k] for k in ("sender_email", "subject", "body"))):
            self.display_message("Correct any field; Enter keeps the extracted value.")
            email = self._read("Sender email", required=not fields["sender_email"],
                               validator=InputValidator.email)
            name = self._read("Sender name", required=False)
            subject = self._read("Subject", required=not fields["subject"])
            fields["sender_email"] = email or fields["sender_email"]
            fields["sender_name"] = name or fields["sender_name"]
            fields["subject"] = subject or fields["subject"]
            if not fields["body"] or not self._yes_no("Keep extracted message text?"):
                fields["body"] = self._multiline("Email message")
            if not self._yes_no("Keep extracted URL list?"):
                fields["urls"] = self._urls()
        fields = self._privacy.sanitise_fields(fields)  # mask corrected user input too
        # No raw path or image bytes persist in the report or get passed to AI.
        metadata = {"filename": self._privacy.blur(image["name"]),
                    "sha256": image["sha256"], "size_bytes": image["size_bytes"],
                    "ocr_method": "local Tesseract", "stored_path": None}
        return fields, metadata

    def _attachments(self) -> Tuple[List[str], List[Dict]]:
        names, details = [], []
        self.display_message("\nAttachments: enter a real file path or just a filename; Enter to finish.")
        while True:
            value = self._read(f"Attachment {len(names) + 1}", required=False, maximum=500)
            if not value:
                return names, details
            try:
                item = self._files.inspect(value)
                if item["is_image"] and self._evidence_store is not None:
                    # Explicitly opt in before keeping an UNREDACTED evidence image.
                    self.display_message("Image evidence may contain personal information.")
                    if self._yes_no("Keep a copy of this image for IT review?"):
                        try:
                            meta = self._evidence_store.save_image(item["path"])
                            item["stored_path"] = meta.get("stored_path")
                        except (ValueError, OSError) as exc:
                            self.display_error(f"Could not save evidence: {exc}")
                # Don't store original file path in JSON, which can reveal usernames.
                item.pop("path", None)
                item["name"] = self._privacy.blur(item["name"])
                names.append(item["name"])
                details.append(item)
                self.display_message(f"  Added: {item['name']}")
            except ValueError as exc:
                self.display_error(str(exc))

    def collect_report(self) -> Dict:
        self.display_header("Submit Email Report")
        viewed = self._yes_no("Did you open/view this email?")
        screenshot = None
        if viewed:
            method = self._choose("How would you like to enter the email?", self.METHODS)
            extracted = self._screenshot() if method == self.METHODS[1] else None
            if extracted:
                fields, screenshot = extracted
                input_method = "screenshot (local OCR)"
            else:
                if method == self.METHODS[1]:
                    self.display_message("Switching to manual entry.")
                fields, input_method = self._typed(), "typed"
            attachments, details = self._attachments()
            reason = self._read("Why do you think it is suspicious", required=False)
            actions = {"clicked_link": self._yes_no("Did you click any link?") if fields["urls"] else False,
                       "opened_attachment": self._yes_no("Did you open any attachment?") if attachments else False,
                       "entered_information": self._yes_no("Did you enter any password or personal information?")}
        else:
            self.display_message("\nNo problem. Give us whatever you know.")
            reason = self._read("Why are you suspicious / why didn't you open it")
            fields = {"sender_email": self._read("Sender email (Enter if unknown)", required=False,
                                                   validator=InputValidator.email) or "Not provided",
                      "sender_name": self._read("Sender display name (Enter if unknown)", required=False) or "Not provided",
                      "subject": self._read("Subject line (Enter if unknown)", required=False) or "Not provided",
                      "body": "", "urls": []}
            attachments, details, input_method = [], [], "typed"
            actions = {"clicked_link": False, "opened_attachment": False, "entered_information": False}
        report = self._privacy.sanitise_fields(fields)
        report.update({"viewed": viewed, "attachments": attachments,
                       "attachment_details": details, "screenshot": screenshot,
                       "input_method": input_method, "reason_for_suspicion": self._privacy.blur(reason) or "Not provided",
                       "actions_taken": actions})
        # Record the keyword scan for compatibility; final priority is Logic's job.
        scan_text = " ".join([report["subject"], report["body"], *report["urls"],
                               report["reason_for_suspicion"] if not viewed else ""])
        report["keyword_scan"] = self._keywords.scan(scan_text, f"{report['sender_name']} {report['sender_email']}")
        return report

    def run_keyword_checker(self) -> None:
        self.display_header("Keyword Checker")
        text = self._multiline("Paste suspicious text")
        sender = self._read("Sender name (optional)", required=False)
        result = self._keywords.scan(text, sender)
        self.display_message("\nKeyword check:")
        for category, words in result["found"].items():
            if words:
                self.display_message(f"  {category}: {', '.join(words)}")
        self.display_message(f"  Level: {result['level']} (score {result['score']})")
        self.display_message("  Keyword scan only. Submit a report for full AI analysis.")

    def collect_filter_criteria(self, threat_levels, statuses) -> Optional[Tuple[str, str]]:
        choice = self._choose("Filter reports by:", ["Show all", "Threat level", "Attack type", "Review status"])
        if choice == "Show all":
            return None
        if choice == "Threat level":
            return "threat_level", self._choose("Threat level:", list(threat_levels) + ["unknown"])
        if choice == "Review status":
            return "review_status", self._choose("Review status:", list(statuses))
        return "attack_type", self._read("Attack type")

    def collect_record_id(self, records: List[Dict]) -> Optional[str]:
        known = {str(r.get("report_id", "")).upper() for r in records}
        while True:
            rid = self._read("Enter report ID (Enter to cancel)", required=False)
            if not rid:
                return None
            if rid.upper() in known:
                return rid
            self.display_error("No report with that ID.")

    def collect_status_update(self, statuses) -> Dict:
        return {"review_status": self._choose("New report status:", list(statuses))}

    def collect_priority_override(self, priorities) -> Dict:
        return {"priority_override": self._choose("New priority:", list(priorities))}

    def collect_review_update(self, record: Dict) -> Dict:
        if record.get("review_stage", "first_review") == "awaiting_second_review":
            assigned = str(record.get("assigned_reviewer") or "")
            self.display_message(f"\nSecond-person review (assigned: {assigned})")
            reviewer = self._read("Your name", maximum=MAX_NAME)
            if reviewer.casefold() != assigned.casefold():
                self.display_error("Only the assigned reviewer may approve/reject.")
                return {"review_action": "unauthorized", "reviewer": reviewer}
            decision = self._choose("Approve or reject?", ["Approve", "Reject"])
            rejection_reason = self._multiline("Rejection reason") if decision == "Reject" else ""
            return {"review_action": "second", "reviewer": reviewer,
                    "approval_decision": decision.lower(), "rejection_reason": rejection_reason}
        self.display_message("\nFirst-person review")
        reviewer = self._read("Your name", maximum=MAX_NAME)
        outcome = self._choose("Investigation outcome:",
                               ["Resolved (real scam)", "False Positive (not a scam)"])
        level = self._choose("Risk level:", ["Low", "High"])
        while True:
            assigned = self._read("Assign next reviewer", maximum=MAX_NAME)
            if assigned.casefold() != reviewer.casefold():
                break
            self.display_error("Assign a different reviewer.")
        note = self._read("Review note (optional)", required=False, maximum=MAX_NOTE)
        return {"review_action": "first", "reviewer": reviewer, "report_outcome": outcome,
                "risk_level": level, "assigned_reviewer": assigned, "note": note}

    def display_assessment(self, record: Dict) -> None:
        self.display_header("PHISHGUARD ASSESSMENT")
        ai = record.get("ai_analysis") or {}
        self.display_message(f"  Report ID : {record.get('report_id', '?')}")
        self.display_message(f"  Priority  : {record.get('priority', '?')}")
        if not ai:
            self.display_message(f"  AI unavailable: {record.get('ai_error', 'manual review')}")
            return
        self.display_message(f"  Mode      : {ai.get('analysis_mode', 'unknown')}")
        self.display_message(f"  Threat    : {str(ai.get('threat_level', '?')).upper()} "
                             f"({ai.get('confidence', 0):.0%} confidence)")
        self.display_message(f"  Attack    : {ai.get('attack_type', '?')}")
        found = [v for k, v in INDICATORS.items() if ai.get(k)]
        self.display_message(f"  Indicators: {', '.join(found) or 'none'}")
        self.display_message(f"  Risk score: {record.get('risk_score', 0)}/100")
        self.display_message(f"  Advice    : {ai.get('recommended_action', '')}")
        self.display_message(f"  Reason    : {ai.get('explanation', '')}")
        for rule in record.get("rules_triggered", []):
            self.display_message(f"  Rule      : {rule}")

    def display_record_list(self, records: List[Dict]) -> None:
        self.display_header(f"Reports ({len(records)})")
        if not records:
            self.display_message("  No reports to show.")
        for r in sorted(records, key=lambda r: str(r.get("report_id", ""))):
            subject = (r.get("report") or {}).get("subject", "")
            self.display_message(f"  {r.get('report_id', '?'):8} "
                                 f"{short(r.get('priority'), 23):23} "
                                 f"{short(r.get('review_status'), 19):19} {short(subject, 35)}")
            if r.get("assigned_reviewer"):
                self.display_message(f"       Assigned: {r['assigned_reviewer']}")

    def display_record_detail(self, record: Dict) -> None:
        report, ai = record.get("report") or {}, record.get("ai_analysis") or {}
        self.display_header(f"Report {record.get('report_id', '?')}")
        for label, value in (("Viewed", report.get("viewed")),
                             ("Sender", f"{report.get('sender_name','')} <{report.get('sender_email','')}>"),
                             ("Subject", report.get("subject", "")),
                             ("Reason", report.get("reason_for_suspicion", "")),
                             ("URLs", ", ".join(report.get("urls", [])) or "none"),
                             ("Attachments", ", ".join(report.get("attachments", [])) or "none"),
                             ("Submitted", report.get("input_method", "typed")),
                             ("Body", report.get("body", ""))):
            self.display_message(f"  {label:14}: {value}")
        for action, value in (report.get("actions_taken") or {}).items():
            self.display_message(f"  {action}: {'Yes' if value else 'No'}")
        if report.get("screenshot"):
            self.display_message("  Screenshot: locally extracted; original image not stored")
        for attachment in report.get("attachment_details", []):
            self.display_message(f"  Attachment metadata: {attachment.get('name')} "
                                 f"SHA-256 {short(attachment.get('sha256'), 18)} "
                                 f"stored copy: {attachment.get('stored_path', 'none')}")
        self.display_message(f"  Priority: {record.get('priority')} | Status: {record.get('review_status')}")
        self.display_message(f"  Risk score: {record.get('risk_score', 0)}/100")
        if ai:
            self.display_message(f"  AI: {ai.get('threat_level')} / {ai.get('attack_type')} "
                                 f"({ai.get('confidence', 0):.0%})")
        self.display_message(f"  Review stage: {record.get('review_stage', 'first_review')}")
        self.display_message(f"  Assigned reviewer: {record.get('assigned_reviewer') or 'unassigned'}")
        for entry in record.get("review_history", []):
            self.display_message(f"  Review history: {entry}")
        for note in record.get("investigation_notes", []):
            self.display_message(f"  Investigation note: {note}")

    def pause(self, text="\nPress Enter to continue...") -> None:
        self._channel.read(text)

