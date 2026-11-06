# ai_manager
# main.py for ai with all classes 

from typing import Dict, Optional, Tuple

from email_report import EmailReport
from indicator_detector import IndicatorDetector
from threat_scorer import ThreatScorer
from attack_classifier import AttackClassifier
from action_recommend import ActionRecommender
from validator import AIValidator
from analysis_result import AnalysisResult

class AIManager:
    """Step 1 of the pipeline: orchestrates the analysis of a raw email report."""
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
    