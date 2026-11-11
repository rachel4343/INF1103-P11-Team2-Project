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

@st.cache_resource
def get_systems():
    gemini = GeminiAPIClient(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent",
        API_KEY
    )
    ai_mgr = AIManager()
    return {
        "analyzer": AnalysisOrchestrator(gemini, ai_mgr),
        "keyword_checker": KeywordChecker(),
        "data_mgr": DataManager(JsonRecordStore(DATA_FILE)),
    }

sys = get_systems()
