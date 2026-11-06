## io_config.py under io_manager.py
"""Shared limits and display labels used across PhishGuard I/O modules."""

MAX_FIELD_LENGTH = 300

MAX_BODY_LENGTH = 5000

MAX_URL_LENGTH = 2000

BODY_END_MARKER = "END"

LINE_WIDTH = 60

MAX_NOTE = 1000

MAX_NAME = 60

MAX_IMAGE = 10 * 1024 * 1024

MAX_FILE = 25 * 1024 * 1024

INDICATORS = {
    "impersonation": "Impersonation",
    "urgency_manipulation": "Urgency / pressure",
    "credential_request": "Credential request",
    "suspicious_link": "Suspicious link",
    "attachment_risk": "Risky attachment",
}
