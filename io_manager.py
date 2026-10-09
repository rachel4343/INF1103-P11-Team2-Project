# ==============================================
#  PHISHGUARD — I/O Manager
#  INF1103 Team Project
# ==============================================

import re
from typing import Dict, List, Optional, Tuple

MAX_FIELD_LENGTH = 300
MAX_BODY_LENGTH = 5000
MAX_URL_LENGTH = 2000
BODY_END_MARKER = "END"
LINE_WIDTH = 60

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
FILENAME_PATTERN = re.compile(r"^[\w\-. ()]+\.[A-Za-z0-9]{1,8}$")

INDICATOR_LABELS = {
    "impersonation": "Impersonation",
    "urgency_manipulation": "Urgency / pressure",
    "credential_request": "Credential request",
    "suspicious_link": "Suspicious link",
    "attachment_risk": "Risky attachment",
}

# ──────────────────────────────────────────────
#  PRIVACY PROTECTION — blur before anything is stored or sent
# ──────────────────────────────────────────────
def blur_privacy(text: str) -> str:
    """Hide NRIC/FIN, phone numbers and email local-parts.

    S1234567A -> S*******A | 91234567 -> 91****67 | john@x.com -> j***@x.com
    The email domain is kept on purpose: it is a key spoofing indicator.
    """
    if not text:
        return text
    text = re.sub(r"\b([STFGMstfgm])\d{7}([A-Za-z])\b", r"\1*******\2", text)
    text = re.sub(r"(?<!\d)([689]\d)\d{4}(\d{2})(?!\d)", r"\1****\2", text)
    text = re.sub(r"([\w.+-])[\w.+-]*@([\w-]+(?:\.[\w-]+)+)", r"\1***@\2", text)
    return text


def clean_text(text: str) -> str:
    """Strip control characters and surrounding whitespace."""
    return "".join(ch for ch in text if ch.isprintable() or ch == "\n").strip()


# ──────────────────────────────────────────────
#  BASIC OUTPUT
# ──────────────────────────────────────────────
def display_message(text: str = "") -> None:
    print(text)


def display_error(text: str) -> None:
    print(f"  [!] {text}")


def display_header(title: str) -> None:
    print("\n" + "=" * LINE_WIDTH)
    print(f"  {title}")
    print("=" * LINE_WIDTH)


def truncate(text, width: int) -> str:
    text = str(text if text is not None else "")
    return text if len(text) <= width else text[: width - 3] + "..."


def yes_no_text(value) -> str:
    return "Yes" if value else "No"

# ──────────────────────────────────────────────
#  VALIDATING INPUT HELPERS — reject and re-prompt
# ──────────────────────────────────────────────
def prompt_text(label: str, required: bool = True, max_length: int = MAX_FIELD_LENGTH,
                validator=None, error_message: str = "Invalid input.") -> str:
    while True:
        value = clean_text(input(f"{label}: "))
        if not value:
            if required:
                display_error("This field is required.")
                continue
            return ""
        if len(value) > max_length:
            display_error(f"Too long (max {max_length} characters).")
            continue
        if validator is not None and not validator(value):
            display_error(error_message)
            continue
        return value


def prompt_yes_no(label: str) -> bool:
    while True:
        answer = input(f"{label} (yes/no): ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        display_error("Please answer yes or no.")

def prompt_choice(label: str, options: List[str], allow_skip: bool = False) -> Optional[str]:
    display_message(label)
    for number, option in enumerate(options, start=1):
        display_message(f"  {number}. {option}")
    suffix = " (Enter to skip)" if allow_skip else ""
    while True:
        raw = input(f"Choose 1-{len(options)}{suffix}: ").strip()
        if allow_skip and not raw:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        display_error(f"Please enter a number from 1 to {len(options)}.")


def prompt_multiline(label: str, max_length: int = MAX_BODY_LENGTH) -> str:
    """Read lines until a line containing only END. Body is required."""
    while True:
        display_message(f"{label} (type {BODY_END_MARKER} on its own line to finish):")
        lines = []
        while True:
            line = input()
            if line.strip() == BODY_END_MARKER:
                break
            lines.append(line)
        text = clean_text("\n".join(lines))
        if not text:
            display_error("This field is required.")
        elif len(text) > max_length:
            display_error(f"Too long (max {max_length} characters). Please shorten it.")
        else:
            return text


def is_valid_email(value: str) -> bool:
    return EMAIL_PATTERN.match(value) is not None


def is_valid_url(value: str) -> bool:
    return " " not in value and "." in value and len(value) <= MAX_URL_LENGTH


def is_valid_filename(value: str) -> bool:
    return FILENAME_PATTERN.match(value) is not None

def prompt_list(label: str, item_validator, error_message: str) -> List[str]:
    """Comma-separated list. Optional; re-prompts if ANY item is invalid."""
    while True:
        raw = clean_text(input(f"{label} (comma-separated, Enter if none): "))
        items = [item.strip() for item in raw.split(",") if item.strip()]
        bad = [item for item in items if not item_validator(item)]
        if bad:
            display_error(f"{error_message}: {', '.join(truncate(b, 40) for b in bad)}")
            continue
        return items


# ──────────────────────────────────────────────
#  COLLECT — employee report (Yes/No flow)
# ──────────────────────────────────────────────
def collect_report_input() -> Dict:
    """Collect, validate and privacy-blur one suspicious-email report."""
    display_header("Submit Email Report")

    viewed = prompt_yes_no("Did you open/view this email?")
    no_actions = {"clicked_link": False, "opened_attachment": False, "entered_information": False}

    if not viewed:
        display_message("\nNo problem. Give us whatever you know.")
        reason = prompt_text("Why are you suspicious / why didn't you open it")
        sender_email = prompt_text("Sender email (Enter if unknown)", required=False,
                                   validator=is_valid_email,
                                   error_message="That doesn't look like an email address.")
        sender_name = prompt_text("Sender display name (Enter if unknown)", required=False)
        subject = prompt_text("Subject line (Enter if unknown)", required=False)
        return {
            "viewed": False,
            "sender_email": sender_email or "Not provided",
            "sender_name": blur_privacy(sender_name) or "Not provided",
            "subject": blur_privacy(subject) or "Not provided",
            "body": "",
            "urls": [],
            "attachments": [],
            "reason_for_suspicion": blur_privacy(reason),
            "actions_taken": no_actions,
        }

    display_message("\nEnter the email details.")
    sender_email = prompt_text("Sender email", validator=is_valid_email,
                               error_message="That doesn't look like an email address.")
    sender_name = prompt_text("Sender display name", required=False)
    subject = prompt_text("Email subject")
    body = prompt_multiline("Email message")
    urls = prompt_list("URLs found", is_valid_url, "Not a valid URL")
    attachments = prompt_list("Attachment file names", is_valid_filename,
                              "Not a valid file name (need a name and extension)")
    reason = prompt_text("Why do you think it is suspicious", required=False)

    display_message("\nWhat did you do with the email?")
    clicked = prompt_yes_no("Did you click any link?") if urls else False
    opened = prompt_yes_no("Did you open any attachment?") if attachments else False
    entered = prompt_yes_no("Did you enter any password or personal information?")

    body_safe = blur_privacy(body)
    if body_safe != body:
        display_message("  Privacy protected: sensitive details in the message were hidden.")

    # The reported sender is the attacker's address, not the employee's
    # personal data, so it is kept as-is for spoofing analysis.
    return {
        "viewed": True,
        "sender_email": sender_email,
        "sender_name": blur_privacy(sender_name) or "Not provided",
        "subject": blur_privacy(subject),
        "body": body_safe,
        "urls": urls,
        "attachments": attachments,
        "reason_for_suspicion": blur_privacy(reason) or "Not provided",
        "actions_taken": {
            "clicked_link": clicked,
            "opened_attachment": opened,
            "entered_information": entered,
        },
    }

# ──────────────────────────────────────────────
#  MENUS AND SELECTION
# ──────────────────────────────────────────────
def show_main_menu() -> int:
    display_header("PHISHGUARD — Main Menu")
    display_message("  1. Submit Email Report")
    display_message("  2. Keyword Checker Tool")
    display_message("  3. Exit")
    while True:
        raw = input("\nChoose (1-3): ").strip()
        if raw in ("1", "2", "3"):
            return int(raw)
        display_error("Please choose 1, 2 or 3.")


KEYWORD_LABELS = {
    "urgency": "Urgency words",
    "credential": "Login/Password words",
    "impersonation": "Impersonation",
    "risky_links": "Risky links",
}


def collect_keyword_text() -> str:
    """Keyword Checker input. Returns "" if the user pressed Enter."""
    display_header("PHISHGUARD Keyword Checker")
    display_message("  Quick offline word check. No AI is used and nothing is saved.")
    return prompt_text("Paste text to scan (Enter to cancel)", required=False,
                       max_length=MAX_BODY_LENGTH)


def display_keyword_results(result: Dict) -> None:
    """Show what logic_manager.scan_keywords() found."""
    display_message("\n  Results:")
    found = result.get("found", {})
    for key, label in KEYWORD_LABELS.items():
        words = found.get(key) or []
        if words:
            display_message(f"    {label}: {', '.join(words)}")

    if result.get("level") == "safe":
        display_message("    No red flags found")
    else:
        display_message(f"    Keyword level: {str(result.get('level')).upper()} "
                        f"(score {result.get('score', 0)})")
    display_message("    Word check only. Submit a report for the full AI assessment.")
    input("\nPress Enter to continue...")

def collect_filter_criteria(threat_levels, statuses) -> Optional[Tuple[str, str]]:
    """Ask how to filter the list. Returns (field, value) or None for 'show all'."""
    field = prompt_choice(
        "\nFilter reports by:",
        ["Show all", "Threat level", "Attack type", "Review status"],
    )
    if field == "Show all":
        return None
    if field == "Threat level":
        return "threat_level", prompt_choice("Threat level:", list(threat_levels) + ["unknown"])
    if field == "Review status":
        return "review_status", prompt_choice("Review status:", list(statuses))
    return "attack_type", prompt_text("Attack type (e.g. credential harvesting)")


def collect_record_id(records: List[Dict]) -> Optional[str]:
    """Ask for a report id that exists. Enter cancels (returns None)."""
    known = {str(r.get("report_id", "")).upper() for r in records}
    while True:
        raw = input("Enter report ID (e.g. PG-0001, Enter to cancel): ").strip()
        if not raw:
            return None
        if raw.upper() in known:
            return raw
        display_error("No report with that ID.")


