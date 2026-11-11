# ==============================================
#  PHISHGUARD — Logic Manager Package
#  INF1103 Phase 2
# ==============================================

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

# A sibling module named logic_manager.py exists at the project root.
# Because this directory is also named logic_manager, plain `import logic_manager`
# resolves to this package instead of the root module. Re-export the legacy
# module-level functions so older imports such as `logic_manager.scan_keywords()`
# keep working alongside the package API.
_compat_path = Path(__file__).resolve().parent.parent / "logic_manager.py"
_compat_spec = spec_from_file_location("_logic_manager_compat", _compat_path)
if _compat_spec and _compat_spec.loader:
    _legacy_logic_manager = module_from_spec(_compat_spec)
    _compat_spec.loader.exec_module(_legacy_logic_manager)
    for _name in (
        "THREAT_LEVELS",
        "REVIEW_STATUSES",
        "PRIORITY_CRITICAL",
        "PRIORITY_URGENT",
        "PRIORITY_HIGH",
        "PRIORITY_SECURITY",
        "PRIORITY_LOW",
        "PRIORITY_MANUAL",
        "PRIORITIES",
        "PRIORITY_RANK",
        "INDICATOR_FIELDS",
        "RULE_INPUT_FIELDS",
        "has_usable_ai_result",
        "count_indicators",
        "confidence_gate",
        "risk_score",
        "risk_breakdown",
        "find_keywords",
        "keyword_level",
        "scan_keywords",
        "report_scan_inputs",
        "scan_report_keywords",
        "apply_keyword_safety_net",
        "read_actions",
        "evaluate_rules",
        "has_conflicting_indicators",
        "escalate_for_user_actions",
        "apply_business_rules",
        "next_report_id",
        "build_final_record",
        "apply_review_update",
        "find_record_index",
        "sort_records_by_priority",
        "verify_it_password",
        "hash_passcode",
    ):
        if hasattr(_legacy_logic_manager, _name):
            globals()[_name] = getattr(_legacy_logic_manager, _name)
    globals()["logic_manager"] = _legacy_logic_manager

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
from . import logic_manager as package_logic_manager