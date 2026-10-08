# ==============================================
#  PHISHGUARD — Logic Manager
#  INF1103 Team Project
#
#  Domain brain: turns the AI's assessment into a decision.
#  The AI Manager owns the API, prompt, schema validation and retries;
#  nothing in this file repeats that work.
#
#  Decision = THREE kinds of evidence, not just confidence:
#     1. severity       -> the AI's threat_level
#     2. corroboration  -> HOW MANY warning signs are true
#     3. confidence     -> how sure the AI is (used as a gate)
#  plus what the employee actually did (clicked / entered a password).
#
#  The team's keyword word list ALSO lives here (menu option 2, the Keyword
#  Checker). It is deterministic and offline, so it is domain logic, not I/O
#  and not AI. In the report flow it acts as a capped safety net behind the
#  AI result: it can raise a report to Security Review, never higher.
# ==============================================

from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────
#  1. CONSTANTS — every number and label lives here
# ──────────────────────────────────────────────
THREAT_LEVELS = ("low", "medium", "high", "critical")

PRIORITY_CRITICAL = "Critical"
PRIORITY_URGENT = "Urgent Security Review"
PRIORITY_HIGH = "High-Priority Review"
PRIORITY_SECURITY = "Security Review"
PRIORITY_LOW = "Low Priority"
PRIORITY_MANUAL = "Manual Review Required"

PRIORITIES = (
    PRIORITY_CRITICAL,
    PRIORITY_URGENT,
    PRIORITY_HIGH,
    PRIORITY_SECURITY,
    PRIORITY_LOW,
    PRIORITY_MANUAL,
)

# Higher number = needs attention sooner. Manual Review ranks ABOVE Low:
# a report nobody has judged yet must never sit below one the system
# judged harmless.
PRIORITY_RANK = {
    PRIORITY_CRITICAL: 6,
    PRIORITY_URGENT: 5,
    PRIORITY_HIGH: 4,
    PRIORITY_SECURITY: 3,
    PRIORITY_MANUAL: 2,
    PRIORITY_LOW: 1,
}


# Confidence needed for each rule. The "corroborated" value is the LOWER bar
# used when 3+ warning signs agree: lots of red flags can make up for a
# hesitant AI. Dismissing a report (Low) never gets a lower bar.
CONF_CRITICAL = 0.85
CONF_CRITICAL_CORROBORATED = 0.75
CONF_CREDENTIAL_LINK = 0.80
CONF_CREDENTIAL_LINK_CORROBORATED = 0.70
CONF_MEDIUM = 0.75
CONF_MEDIUM_CORROBORATED = 0.65
CONF_LOW = 0.90
CORROBORATION_MIN_INDICATORS = 3

# The AI fields the rules read. (Full schema validation is the AI Manager's job.)
RULE_INPUT_FIELDS = (
    "threat_level",
    "confidence",
    "impersonation",
    "urgency_manipulation",
    "credential_request",
    "suspicious_link",
    "attachment_risk",
)

INDICATOR_FIELDS = (
    "impersonation",
    "urgency_manipulation",
    "credential_request",
    "suspicious_link",
    "attachment_risk",
)

# Plain-English names for the five warning signs (used in explanations).
INDICATOR_LABELS = {
    "impersonation": "impersonation",
    "urgency_manipulation": "urgency pressure",
    "credential_request": "credential request",
    "suspicious_link": "suspicious link",
    "attachment_risk": "risky attachment",
}



# ──────────────────────────────────────────────
#  2. CAN THE RULES RUN? (not full schema validation: that is the AI Manager's job)
# ──────────────────────────────────────────────
def has_usable_ai_result(ai_result) -> bool:
    """True if the AI Manager handed over a result the rules can safely read.

    The AI Manager validates the schema and retries. It passes None when the
    AI failed or stayed invalid after retry. This supports the brief's rule
    "required AI fields missing / invalid after retry -> Manual Review Required".

    Beyond "no field is None", this also checks the two fields whose WRONG TYPE
    would crash the rules (a string confidence would break `conf >= 0.85`, an
    unknown threat level would break the lookup tables). It is a crash guard,
    not a second schema validator.
    """
    if not isinstance(ai_result, dict):
        return False
    if any(ai_result.get(field) is None for field in RULE_INPUT_FIELDS):
        return False
    conf = ai_result["confidence"]
    return (
        ai_result["threat_level"] in THREAT_LEVELS
        and isinstance(conf, (int, float))
        and not isinstance(conf, bool)
        and 0.0 <= conf <= 1.0
    )