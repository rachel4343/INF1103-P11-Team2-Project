"""Validation for locally generated phishing analysis results."""

from .config import Config


class AIValidator:
    """Validates required analysis fields and their types."""

    def validate(self, data: dict) -> bool:
        if not isinstance(data, dict):
            return False

        for field in Config.RULE_INPUT_FIELDS:
            if field not in data or data[field] is None:
                return False

        if data.get("threat_level") not in Config.THREAT_LEVELS:
            return False

        confidence = data.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= confidence <= 1.0
        ):
            return False

        return all(
            isinstance(data.get(field), bool)
            for field in Config.BOOLEAN_FIELDS
        )
