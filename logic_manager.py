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



# ──────────────────────────────────────────────
#  3. EVIDENCE HELPERS — the building blocks of the rules
# ──────────────────────────────────────────────
def count_indicators(ai: Dict) -> int:
    """How many of the 5 warning signs are true (0 to 5)."""
    return sum(1 for field in INDICATOR_FIELDS if ai.get(field))


def confidence_gate(ai: Dict, normal: float, corroborated: float) -> str:
    """Is the AI confident ENOUGH? Returns a plain-language reason, or "" if not.

    Passes if confidence >= the normal bar, OR if 3+ warning signs agree and
    confidence >= the lower corroborated bar. The text goes into the record
    so IT can see WHY a rule fired.
    """
    conf = ai["confidence"]
    if conf >= normal:
        return f"{conf:.0%} sure"
    indicators = count_indicators(ai)
    if indicators >= CORROBORATION_MIN_INDICATORS and conf >= corroborated:
        return f"{conf:.0%} sure, backed by {indicators} warning signs"
    return ""




# ──────────────────────────────────────────────
#  4. BUSINESS RULES
# ──────────────────────────────────────────────
def evaluate_rules(ai: Dict) -> List[Tuple[str, str]]:
    """Return EVERY (priority, reason) whose conditions match the AI fields."""
    matched = []
    level = ai["threat_level"]
    indicators = count_indicators(ai)

    # Rule 1: critical severity + enough confidence (or strong corroboration)
    gate = confidence_gate(ai, CONF_CRITICAL, CONF_CRITICAL_CORROBORATED)
    if level == "critical" and gate:
        matched.append((PRIORITY_CRITICAL,
                        f"Email check: {PRIORITY_CRITICAL}, because the AI rated the threat critical ({gate})"))

    # Rule 2: credentials requested via a suspicious link (multi-condition)
    gate = confidence_gate(ai, CONF_CREDENTIAL_LINK, CONF_CREDENTIAL_LINK_CORROBORATED)
    if ai["credential_request"] and ai["suspicious_link"] and gate:
        matched.append((PRIORITY_URGENT,
                        f"Email check: {PRIORITY_URGENT}, because the email asks for credentials through a suspicious link ({gate})"))

    # Rule 3: high severity backed by impersonation + urgency, or by 3+ warning signs
    if level == "high":
        if ai["impersonation"] and ai["urgency_manipulation"]:
            matched.append((PRIORITY_HIGH,
                            f"Email check: {PRIORITY_HIGH}, because the AI rated the threat high and found impersonation and urgency pressure"))
        elif indicators >= CORROBORATION_MIN_INDICATORS:
            matched.append((PRIORITY_HIGH,
                            f"Email check: {PRIORITY_HIGH}, because the AI rated the threat high and found {indicators} warning signs"))

    # Rule 4: medium severity + enough confidence (or corroboration)
    gate = confidence_gate(ai, CONF_MEDIUM, CONF_MEDIUM_CORROBORATED)
    if level == "medium" and gate:
        matched.append((PRIORITY_SECURITY,
                        f"Email check: {PRIORITY_SECURITY}, because the AI rated the threat medium ({gate})"))

    # Rule 5: dismiss as low ONLY with very high confidence and no suspicious link
    if level == "low" and ai["confidence"] >= CONF_LOW and not ai["suspicious_link"]:
        matched.append((PRIORITY_LOW,
                        f"Email check: {PRIORITY_LOW}, because the AI rated the threat low ({ai['confidence']:.0%} sure) "
                        f"and found no suspicious link"))

    return matched




def apply_business_rules(report: Optional[Dict], ai_result) -> Dict:
    """Decide the final priority for one report.

    Never raises when the AI result is missing: it routes to Manual Review.
    """
    if not has_usable_ai_result(ai_result):
        priority = PRIORITY_MANUAL
        triggered = [f"Email check: {PRIORITY_MANUAL}, because the AI result was unavailable or incomplete"]
    else:
        ai = ai_result
        matched = evaluate_rules(ai)
        if matched:
            # Conflicting rules: the HIGHEST-risk outcome wins
            best = max(matched, key=lambda m: PRIORITY_RANK[m[0]])
            priority = best[0]
            triggered = [m[1] for m in matched]
        else:
            priority = PRIORITY_MANUAL
            triggered = [f"Email check: {PRIORITY_MANUAL}, because the AI was not sure enough to decide"]

    return {
        "priority": priority,
        "rules_triggered": triggered,
    }