import re
from typing import Dict, Optional, Tuple
 
THREAT_LEVELS = ("low", "medium", "high", "critical")
 
RULE_INPUT_FIELDS = (
    "threat_level",
    "confidence",
    "impersonation",
    "urgency_manipulation",
    "credential_request",
    "suspicious_link",
    "attachment_risk",
)
 
WEIGHTS = {
    "impersonation": 2,
    "urgency_manipulation": 1,
    "credential_request": 3,
    "suspicious_link": 3,
    "attachment_risk": 2,
}
 
 
def validate_ai_schema(data: dict) -> bool:
    """Validates that the AI result dictionary matches all expected keys and types."""
    if not isinstance(data, dict):
        return False
 
    # Verify required input fields exist
    for field in RULE_INPUT_FIELDS:
        if field not in data or data[field] is None:
            return False
 
    # Check threat level validity
    if data.get("threat_level") not in THREAT_LEVELS:
        return False
 
    # Check confidence range (0.0 to 1.0); bool is not a valid confidence
    conf = data.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        return False
 
    # Check boolean indicators
    boolean_fields = (
        "impersonation",
        "urgency_manipulation",
        "credential_request",
        "suspicious_link",
        "attachment_risk",
    )
    for field in boolean_fields:
        if not isinstance(data.get(field), bool):
            return False
 
    return True
 
 
def analyze_email(report: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """Analyzes a raw email report as Step 1 of the processing pipeline.
 
    Returns:
        (ai_result_dict, None) if analysis succeeds.
        (None, error_message_str) if an error occurs.
    """
    try:
        subject = str(report.get("subject") or "")
        body = str(report.get("body") or "")
        sender_name = str(report.get("sender_name") or report.get("sender") or "")
        sender_email = str(report.get("sender_email") or "")
 
        full_text = f"{subject} {body}".lower()
        sender_info = f"{sender_name} {sender_email}".lower()
 
        links = report.get("links") or report.get("urls") or []
        if isinstance(links, str):
            links = [links]
 
        attachments = report.get("attachments") or []
        if isinstance(attachments, str):
            attachments = [attachments]
 
        # Detection rules 
        impersonation = (
            bool(re.search(r"\b(it|support|admin|helpdesk|security)\b", sender_info))
            and bool(re.search(r"\b(verify|account|login|suspend)", full_text))
        )
 
        urgency_manipulation = bool(
            re.search(r"\b(urgent|immediately|expir\w*|suspend\w*|deadline)\b", full_text)
        )
 
        credential_request = bool(
            re.search(r"\b(password|otp|credentials?|username|log ?in|pin)\b", full_text)
        )
 
        suspicious_link = bool(
    re.search(
        r"(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|ow\.ly|cutt\.ly)",
        " ".join(map(str, links)).lower()
    )
)
 
        attachment_risk = any(
            str(a).lower().endswith((".exe", ".scr", ".js", ".zip", ".docm"))
            for a in attachments
        )
 
        signs = {
            "impersonation": impersonation,
            "urgency_manipulation": urgency_manipulation,
            "credential_request": credential_request,
            "suspicious_link": suspicious_link,
            "attachment_risk": attachment_risk,
        }
 
        # Weighted score evaluation 
        score = sum(WEIGHTS[k] for k, v in signs.items() if v)
 
        if score >= 8:
            threat_level, confidence = "critical", 0.90
        elif score >= 5:
            threat_level, confidence = "high", 0.85
        elif score >= 3:
            threat_level, confidence = "medium", 0.75
        elif score >= 1:
            threat_level, confidence = "low", 0.65
        else:
            threat_level, confidence = "low", 0.95
 
        # Primary attack classification 
        if credential_request or (suspicious_link and impersonation):
            attack_type = "credential harvesting"
        elif attachment_risk:
            attack_type = "malware delivery"
        elif impersonation:
            attack_type = "executive impersonation"
        elif score > 0:
            attack_type = "suspicious spam"
        else:
            attack_type = "none"
 
        #  Action recommendations
        if threat_level in ("critical", "high"):
            recommended_action = "Do not click links or open attachments. Report to Security."
        elif threat_level == "medium":
            recommended_action = "Verify sender identity via trusted secondary channel."
        else:
            recommended_action = "No immediate action required."
 
        detected = [k.replace("_", " ") for k, v in signs.items() if v]
        explanation = (
            f"Flagged indicators: {', '.join(detected)}."
            if detected
            else "No suspicious indicators detected."
        )
 
        # Output data payload 
        ai_result = {
            "threat_level": threat_level,
            "attack_type": attack_type,
            "confidence": confidence,
            "impersonation": impersonation,
            "urgency_manipulation": urgency_manipulation,
            "credential_request": credential_request,
            "suspicious_link": suspicious_link,
            "attachment_risk": attachment_risk,
            "recommended_action": recommended_action,
            "explanation": explanation,
        }
 
        # Schema validation guard
        if not validate_ai_schema(ai_result):
            return (None, "AI assessment failed schema validation.")
 
        return (ai_result, None)
 
    except Exception as e:
        return (None, f"AI processing error: {str(e)}")