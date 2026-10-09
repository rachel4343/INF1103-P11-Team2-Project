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