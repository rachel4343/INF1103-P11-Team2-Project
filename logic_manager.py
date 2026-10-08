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

import re
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


# ── Risk score (0-100) ──
# Design principle: severity is worth 60 points, warning signs 40 points.
#   * Threat level moves in steps of 20, so a higher threat level always
#     outweighs any single warning sign.
#   * The five warning signs total exactly 40 (10+10+7+7+6), ranked by how
#     directly each one leads to compromise: credentials and links are the
#     direct route in, impersonation and attachments need more steps, and
#     urgency alone is only pressure.
#   * 60 + 40 = 100, so the scale needs no arbitrary cap.
THREAT_POINTS = {"low": 0, "medium": 20, "high": 40, "critical": 60}
INDICATOR_POINTS = {
    "credential_request": 10,
    "suspicious_link": 10,
    "impersonation": 7,
    "attachment_risk": 7,
    "urgency_manipulation": 6,
}


# ── Keyword Checker (menu option 2) and keyword safety net ──
# Our own word database. Add/remove words here anytime.
KEYWORD_DATABASE = {
    "urgency": [
        "urgent", "immediately", "now", "expire", "deadline", "suspend",
        "block", "close", "act fast", "right now", "limited time",
    ],
    "credential": [
        "password", "login", "verify", "account", "otp", "pin",
        "username", "sign in", "confirm", "credential",
    ],
    "impersonation": [
        "it support", "helpdesk", "security team", "hr department",
        "admin", "system admin", "technical team", "it department",
    ],
    "risky_links": [
        "bit.ly", "tinyurl", "goo.gl", "login-verify", "account-verify",
    ],
}

# Points per word found, per category
KEYWORD_POINTS = {"urgency": 1, "credential": 2, "impersonation": 2, "risky_links": 2}

# Score -> keyword level, checked from the top. Below 1 point = "safe".
KEYWORD_LEVELS = ((6, "critical"), (4, "high"), (2, "medium"), (1, "low"))

# Keyword levels that may raise a report. The raise is capped at Security Review,
# so keywords alone can never create a Critical or Urgent report.
KEYWORD_ESCALATION_LEVELS = ("high", "critical")


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



def risk_score(ai: Dict) -> int:
    """0-100 score from threat level + true warning signs (no confidence)."""
    score = THREAT_POINTS.get(ai.get("threat_level"), 0)
    for field, points in INDICATOR_POINTS.items():
        if ai.get(field):
            score += points
    return score


def risk_breakdown(ai: Dict) -> str:
    """Show the working behind the risk score, e.g.
    "medium threat 20 + suspicious link 10 = 30"."""
    level = ai.get("threat_level")
    parts = [f"{level} threat {THREAT_POINTS.get(level, 0)}"]
    for field, points in INDICATOR_POINTS.items():
        if ai.get(field):
            parts.append(f"{INDICATOR_LABELS[field]} {points}")
    return " + ".join(parts) + f" = {risk_score(ai)}"




# ──────────────────────────────────────────────
#  3b. KEYWORD CHECKER — the team's word database (menu option 2)
#      Pure functions: the I/O Manager collects the text and shows the result.
# ──────────────────────────────────────────────
def find_keywords(words: List[str], text: str) -> List[str]:
    """Which of `words` appear in `text` (already lower-case)?

    Matches whole words only, allowing simple endings (-s, -es, -ed, -d), so
    "suspended" matches "suspend" but "know" does not match "now", "shopping"
    does not match "pin" and "accounting" does not match "account".
    """
    found = []
    for word in words:
        pattern = r"(?<![a-z0-9])" + re.escape(word) + r"(?:s|es|ed|d)?(?![a-z0-9])"
        if re.search(pattern, text):
            found.append(word)
    return found


def keyword_level(score: int) -> str:
    """Turn a keyword score into safe / low / medium / high / critical."""
    for minimum, level in KEYWORD_LEVELS:
        if score >= minimum:
            return level
    return "safe"


def scan_keywords(text: str, sender: str = "") -> Dict:
    """Check text against the word database.

    Returns {"found": {category: [words]}, "score": int, "level": str}.
    Impersonation words are looked for in the SENDER only, and only when
    credential words are also present (impersonation + a credential request
    is the dangerous combination).
    """
    text = (text or "").lower()
    sender = (sender or "").lower()

    found = {
        "urgency": find_keywords(KEYWORD_DATABASE["urgency"], text),
        "credential": find_keywords(KEYWORD_DATABASE["credential"], text),
        "impersonation": [],
        "risky_links": find_keywords(KEYWORD_DATABASE["risky_links"], text),
    }
    if found["credential"]:
        found["impersonation"] = find_keywords(KEYWORD_DATABASE["impersonation"], sender)

    score = sum(KEYWORD_POINTS[category] * len(words) for category, words in found.items())
    return {"found": found, "score": score, "level": keyword_level(score)}


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

    Returns {"priority", "rules_triggered", "keyword_scan"}.
    Never raises when the AI result is missing: it routes to Manual Review.
    """
    keyword_scan = scan_report_keywords(report)

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
        elif ai["threat_level"] in ("high", "critical"):
            # Fallback: the AI called it serious but was not confident enough for
            # any rule. A serious threat must never rank below Security Review.
            priority = PRIORITY_SECURITY
            triggered = [f"Email check: {PRIORITY_SECURITY}, because the AI rated the threat {ai['threat_level']} "
                         f"but was not sure enough for a firm rule"]
        else:
            priority = PRIORITY_MANUAL
            triggered = [f"Email check: {PRIORITY_MANUAL}, because the AI was not sure enough to decide"]

        # Conflicting indicators (low threat but warning signs): never stay below Security Review
        if has_conflicting_indicators(ai) and PRIORITY_RANK[priority] < PRIORITY_RANK[PRIORITY_SECURITY]:
            priority = PRIORITY_SECURITY
            triggered.append(f"Upgraded to {PRIORITY_SECURITY} because the AI rated it low but still found warning signs")

    # Keyword safety net (can only raise, capped at Security Review)
    priority, triggered = apply_keyword_safety_net(priority, keyword_scan, triggered)

    return {
        "priority": priority,
        "rules_triggered": triggered,
        "keyword_scan": keyword_scan,
    }



def has_conflicting_indicators(ai: Dict) -> bool:
    """A 'low' threat level that still has warning signs switched on."""
    return ai["threat_level"] == "low" and count_indicators(ai) > 0




def report_scan_inputs(report: Optional[Dict]) -> Tuple[str, str]:
    """Pick the (text, sender) to keyword-scan out of a report dictionary.

    Text = subject + body + URLs. For an email the employee did NOT open there
    is no body, so their reason for suspicion is scanned instead.
    """
    report = report or {}
    parts = [str(report.get("subject") or ""), str(report.get("body") or "")]

    urls = report.get("urls") or report.get("links") or []
    if isinstance(urls, str):
        urls = [urls]
    parts.extend(str(url) for url in urls)

    if report.get("viewed") is False:
        parts.append(str(report.get("reason_for_suspicion") or report.get("reason_not_viewed") or ""))

    sender = f"{report.get('sender_name') or ''} {report.get('sender_email') or report.get('sender') or ''}"
    return " ".join(parts).strip(), sender.strip()


def scan_report_keywords(report: Optional[Dict]) -> Dict:
    """Keyword-scan one employee report."""
    text, sender = report_scan_inputs(report)
    return scan_keywords(text, sender)


def apply_keyword_safety_net(priority: str, scan: Dict, triggered: List[str]) -> Tuple[str, List[str]]:
    """Raise a priority to Security Review when the keywords look dangerous.

    A safety net behind the AI, not a second judge: it only ever RAISES a
    priority, and never above Security Review. It matters most when the AI
    was unavailable or sure the email was harmless while the wording says otherwise.
    """
    if scan["level"] in KEYWORD_ESCALATION_LEVELS and PRIORITY_RANK[priority] < PRIORITY_RANK[PRIORITY_SECURITY]:
        words = sum(len(group) for group in scan["found"].values())
        return PRIORITY_SECURITY, triggered + [
            f"Upgraded to {PRIORITY_SECURITY} because the wording contains {words} red-flag words"]
    return priority, triggered