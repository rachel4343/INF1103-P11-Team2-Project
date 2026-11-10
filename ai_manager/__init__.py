# ==============================================
#  PHISHGUARD — AI Manager Package
#  INF1103 Phase 2
# ==============================================

# Configuration
from .config import Config

# Data Models
from .email_report import EmailReport
from .analysis_result import AnalysisResult

# Processing Components
from .indicator_detector import IndicatorDetector
from .threat_scorer import ThreatScorer
from .attack_classifier import AttackClassifier
from .action_recommend import ActionRecommender
from .validator import AIValidator

# Main Entry Point
from .ai_manager import AIManager