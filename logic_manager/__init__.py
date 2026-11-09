# ==============================================
#  PHISHGUARD — Logic Manager Package
#  INF1103 Phase 2
# ==============================================

# Core Coordinator
from .logic_manager import LogicManager

# Supporting Services
from .audit_trail import AuditTrail
from .action_escalator import ActionEscalator
from .risk_scorer import RiskScorer
from .rule_engine import RuleEngine
from .statistics_report import StatisticsReport

# Base Rule Class
from .priority_rule import PriorityRule

# Individual Priority Rules
from .critical_threat_rule import CriticalThreatRule
from .credential_link_rule import CredentialLinkRule
from .high_threat_rule import HighThreatRule
from .medium_threat_rule import MediumThreatRule
from .low_threat_rule import LowThreatRule

# Keep backward compatibility
from . import logic_manager