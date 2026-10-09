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