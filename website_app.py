# ==============================================
#  PHISHGUARD — Streamlit Web Interface
#  Imports everything from your main file 
# ==============================================

import streamlit as st
from concurrent.futures import ThreadPoolExecutor

# ── IMPORT FROM YOUR MAIN FILE — ONE LINE  ──
from phishing_guard_main import (
    GeminiAPIClient,
    AnalysisOrchestrator,
    KeywordChecker,
    DataManager,
    JsonRecordStore,
    LogicManager,
    AIManager,
    IT_PASSWORD,
    DATA_FILE,
)

# ── Initialise — same as CLI ──
API_KEY = __import__('os').environ.get("GEMINI_API_KEY", "")

