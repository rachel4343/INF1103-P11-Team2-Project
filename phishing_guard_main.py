# ==============================================
#  PHISHGUARD — Main Program (OOP Refactored)
#  INF1103 Phase 2
# ==============================================

import getpass
import json
import os
import requests
from typing import Dict, Optional, Tuple

# ── Import All Managers ───────────────────────
from ai_manager import AIManager
from data_manager import DataManager, JsonRecordStore
from io_manager import (
    display_header,
    display_message,
    display_error,
    display_assessment,
    display_record_list,
    display_record_detail,
    display_keyword_results,
    prompt_menu_number,
    prompt_choice,
    prompt_text,
    collect_report_input,
    collect_review_update,
    collect_record_id,
    collect_keyword_text,
    prompt_it_password,
)
from logic_manager import (
    LogicManager,
    REVIEW_STATUSES,
    PRIORITIES,
    THREAT_LEVELS,
)
# ── Configuration ─────────────────────────────
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent"
API_KEY = os.environ.get("GEMINI_API_KEY", "")
DATA_FILE = "phishguard_reports.json"