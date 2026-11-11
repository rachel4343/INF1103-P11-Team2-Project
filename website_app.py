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

# ── Threaded AI Call ──
def threaded_analyze(report):
    with ThreadPoolExecutor() as ex:
        future = ex.submit(sys["analyzer"].analyze, report)
        return future.result(timeout=30)

# ── Web UI — ONLY buttons & display ✅ ──
st.set_page_config(page_title="PhishGuard", page_icon="🛡️")
st.title("🛡️ PhishGuard — Web Interface")

text = st.text_area("Paste text to scan")
if st.button("Scan"):
    report = {"body": text, "subject": "", "sender_name": "", "sender_email": "", "viewed": True}
    with st.spinner("Analysing..."):
        result, err = threaded_analyze(report)
    if result:
        st.write(f"**Threat:** {result['threat_level']}")
        st.write(f"**Confidence:** {result['confidence']:.0%}")
    else:
        st.error(f"Error: {err}")