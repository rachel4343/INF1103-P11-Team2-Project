# config.py under ai_manager.py
# the constsants: threat levels, weights, risky extension

class Config:
    """Central configuration: constants shared across PhishGuard classes."""

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
    BOOLEAN_FIELDS = (
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

    RISKY_ATTACHMENT_EXTENSIONS = (
        ".exe", ".scr", ".js", ".zip", ".docm",
        ".xlsm", ".bat", ".cmd", ".vbs",
    )