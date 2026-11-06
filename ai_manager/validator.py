#validator.py under ai_manager.py
#validate result follows the expected data structure, contains the required fields and uses the correct data types

from config import Config

class AIValidator:
    """Validates that an AI result dictionary has the expected keys and types."""
def validate(self, data: dict) -> bool:
        if not isinstance(data, dict):
            return False

        for field in Config.RULE_INPUT_FIELDS:
            if field not in data or data[field] is None:
                return False

        if data.get("threat_level") not in Config.THREAT_LEVELS:
            return False

        conf = data.get("confidence")
        # bool is not a valid confidence
        if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
            return False

        for field in Config.BOOLEAN_FIELDS:
            if not isinstance(data.get(field), bool):
                return False

        return True