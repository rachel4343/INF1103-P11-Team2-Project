# action_recommnedation.py under ai_manager.py
# this is to recommend what to do next when threat level is critical, high or medium

class ActionRecommender:
    """Maps a threat level to a recommended user action."""

    def recommend(self, threat_level: str) -> str:
        if threat_level in ("critical", "high"):
            return "Do not click links or open attachments. Report to Security."
        if threat_level == "medium":
            return "Verify sender identity via trusted secondary channel."
        return "No immediate action required."