"""Orchestrates local phishing analysis from detection through validation."""

from typing import Dict, Optional, Tuple

from .action_recommend import ActionRecommender
from .analysis_result import AnalysisResult
from .attack_classifier import AttackClassifier
from .email_report import EmailReport
from .indicator_detector import IndicatorDetector
from .threat_scorer import ThreatScorer
from .validator import AIValidator


class AIManager:
    """Orchestrates the analysis of a raw email report."""

    def __init__(
        self,
        detector: Optional[IndicatorDetector] = None,
        scorer: Optional[ThreatScorer] = None,
        classifier: Optional[AttackClassifier] = None,
        recommender: Optional[ActionRecommender] = None,
        validator: Optional[AIValidator] = None,
    ):
        self.detector = detector or IndicatorDetector()
        self.scorer = scorer or ThreatScorer()
        self.classifier = classifier or AttackClassifier()
        self.recommender = recommender or ActionRecommender()
        self.validator = validator or AIValidator()

    def analyze_email(
        self, report: Dict
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Return the analysis result, or an error message if analysis fails."""
        try:
            email = EmailReport.from_dict(report)
            signs = self.detector.detect(email)
            score = self.scorer.score(signs)
            threat_level, confidence = self.scorer.assess(score)

            result = AnalysisResult(
                threat_level=threat_level,
                attack_type=self.classifier.classify(signs, score),
                confidence=confidence,
                impersonation=signs["impersonation"],
                urgency_manipulation=signs["urgency_manipulation"],
                credential_request=signs["credential_request"],
                suspicious_link=signs["suspicious_link"],
                attachment_risk=signs["attachment_risk"],
                recommended_action=self.recommender.recommend(threat_level),
                explanation=self._build_explanation(signs),
            ).to_dict()

            if not self.validator.validate(result):
                return None, "AI assessment failed schema validation."
            return result, None
        except Exception as exc:
            return None, f"AI processing error: {exc}"

    @staticmethod
    def _build_explanation(signs: Dict[str, bool]) -> str:
        detected = [key.replace("_", " ") for key, value in signs.items() if value]
        if detected:
            return f"Flagged indicators: {', '.join(detected)}."
        return "No suspicious indicators detected."
