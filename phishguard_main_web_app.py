# ==============================================
# PHISHGUARD — Streamlit Web Interface
# Redesigned UI: dashboard, sidebar, report cards
# ==============================================

import os
import tempfile

import streamlit as st

from ai_manager import AIManager
from data_manager import DataManager, JsonRecordStore
from io_manager import AttachmentReader, ExtractionError, TesseractExtractor
from io_manager.keyword_checker import KeywordChecker
from logic_manager import LogicManager
from phishing_guard_main import API_URL, AnalysisOrchestrator, GeminiAPIClient




class PhishGuardWebApp:
    """Streamlit interface for the PhishGuard application workflows."""

    MENU_OPTIONS = (
        "Dashboard",
        "Submit Report",
        "Keyword Checker",
        "Find a Report",
        "IT Security Review",
    )

    DATA_FILE = os.environ.get("PHISHGUARD_DATA_FILE", "phishguard_reports.json")

    def __init__(self):
        gemini = GeminiAPIClient(API_URL, os.environ.get("GEMINI_API_KEY", ""))
        self.analyzer = AnalysisOrchestrator(gemini, AIManager())
        self.keyword_checker = KeywordChecker()
        self.store = JsonRecordStore(self.DATA_FILE)
        self.data_manager = DataManager(self.store)
        self.logic_manager = LogicManager()
        self.attachment_reader = AttachmentReader()
        self.ocr_extractor = TesseractExtractor()

    # --------------------------------------------------
    # APPLICATION LAYOUT
    # --------------------------------------------------

    def render(self):
        st.set_page_config(
            page_title="PhishGuard",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded",
        )

        entered_api_key = st.sidebar.text_input(
            "Gemini API key",
            type="password",
            key="gemini_api_key_input",
            placeholder="Enter your Gemini API key",
            help=(
                "Used for this Streamlit session only. Leave blank to use "
                "the server's GEMINI_API_KEY setting."
            ),
        ).strip()
        api_key = entered_api_key or os.environ.get("GEMINI_API_KEY", "")
        gemini = GeminiAPIClient(API_URL, api_key)
        self.analyzer = AnalysisOrchestrator(gemini, AIManager())

        if gemini.enabled:
            st.sidebar.success(
                "Gemini is configured. If unavailable, analysis falls back offline."
            )
        else:
            st.sidebar.warning(
                "Offline analysis. Enter a Gemini API key to enable online analysis."
            )

        self._apply_custom_styles()
        choice = self._render_sidebar()

        if choice == "Dashboard":
            self._render_dashboard()
        elif choice == "Submit Report":
            self._render_report_submission()
        elif choice == "Keyword Checker":
            self._render_keyword_checker()
        elif choice == "Find a Report":
            self._render_report_search()
        elif choice == "IT Security Review":
            self._render_it_review()

    @staticmethod
    def _apply_custom_styles():
        """Apply presentation-only CSS. This does not change application logic."""
        st.markdown(
            """
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@600;700&display=swap');

                :root {
                    color-scheme: light;
                    --pg-bg: #f3f7ff;
                    --pg-surface: #ffffff;
                    --pg-ink: #0f1f3d;
                    --pg-text: #25324b;
                    --pg-muted: #64748b;
                    --pg-line: #e2e9f5;
                    --pg-line-strong: #c9d6ec;
                    --pg-blue: #2563eb;
                    --pg-indigo: #4f46e5;
                    --pg-violet: #7c3aed;
                    --pg-cyan: #06b6d4;
                    --pg-green: #10b981;
                    --pg-amber: #f59e0b;
                    --pg-red: #ef4444;
                    --pg-shadow: 0 1px 2px rgba(15, 31, 61, 0.04), 0 10px 30px rgba(37, 99, 235, 0.08);
                    --pg-shadow-hover: 0 2px 4px rgba(15, 31, 61, 0.05), 0 18px 44px rgba(37, 99, 235, 0.18);
                }

                html, body, .stApp, [class*="css"] {
                    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
                }

                @keyframes pg-rise {
                    from { opacity: 0; transform: translateY(14px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                @keyframes pg-flow {
                    0% { background-position: 0% 50%; }
                    100% { background-position: 200% 50%; }
                }
                @keyframes pg-float {
                    0%, 100% { transform: translate(0, 0) scale(1); }
                    50% { transform: translate(-50px, 40px) scale(1.1); }
                }
                @keyframes pg-stripes {
                    from { background-position: 0 0, 0 0; }
                    to { background-position: 40px 0, 0 0; }
                }
                @keyframes pg-pulse {
                    0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.5); }
                    50% { box-shadow: 0 0 0 7px rgba(16, 185, 129, 0); }
                }

                /* ---------- Canvas ---------- */
                .stApp, [data-testid="stAppViewContainer"] {
                    background:
                        radial-gradient(900px 520px at 92% -8%, rgba(99, 102, 241, 0.16), transparent 62%),
                        radial-gradient(760px 480px at -6% 8%, rgba(6, 182, 212, 0.15), transparent 62%),
                        radial-gradient(800px 520px at 55% 115%, rgba(124, 58, 237, 0.10), transparent 62%),
                        linear-gradient(180deg, #f7faff 0%, #eef3fc 100%);
                    background-attachment: fixed;
                    color: var(--pg-text);
                }

                .stApp::before {
                    content: "";
                    position: fixed;
                    inset: 0;
                    pointer-events: none;
                    background-image: radial-gradient(rgba(37, 99, 235, 0.16) 1px, transparent 1.2px);
                    background-size: 26px 26px;
                    mask-image: radial-gradient(ellipse at 60% 0%, #000 15%, transparent 70%);
                    -webkit-mask-image: radial-gradient(ellipse at 60% 0%, #000 15%, transparent 70%);
                    z-index: 0;
                }

                .stApp::after {
                    content: "";
                    position: fixed;
                    width: 460px; height: 460px;
                    top: 12%; right: -120px;
                    background: radial-gradient(circle, rgba(79, 70, 229, 0.16), transparent 68%);
                    filter: blur(30px);
                    pointer-events: none;
                    animation: pg-float 16s ease-in-out infinite;
                    z-index: 0;
                }

                header[data-testid="stHeader"] {
                    background: rgba(247, 250, 255, 0.75);
                    backdrop-filter: blur(12px);
                    border-bottom: 1px solid var(--pg-line);
                }

                header[data-testid="stHeader"]::after {
                    content: "";
                    position: absolute;
                    left: 0; right: 0; bottom: -1px;
                    height: 3px;
                    background: linear-gradient(90deg, #06b6d4, #2563eb, #7c3aed, #06b6d4);
                    background-size: 200% 100%;
                    animation: pg-flow 7s linear infinite;
                }

                .block-container {
                    padding-top: 2.4rem;
                    padding-bottom: 3rem;
                    max-width: 1450px;
                    position: relative;
                    z-index: 1;
                    animation: pg-rise 0.55s ease both;
                }

                /* ---------- Typography ---------- */
                h1, h2, h3, h4 {
                    color: var(--pg-ink);
                    letter-spacing: -0.02em;
                }

                h1 {
                    font-size: 2.6rem !important;
                    font-weight: 800 !important;
                    background: linear-gradient(95deg, #0f1f3d 0%, #1d4ed8 55%, #7c3aed 100%);
                    -webkit-background-clip: text;
                    background-clip: text;
                    -webkit-text-fill-color: transparent;
                    padding-bottom: 4px;
                }

                h1::after {
                    content: "";
                    display: block;
                    width: 90px; height: 5px;
                    margin-top: 10px;
                    border-radius: 6px;
                    background: linear-gradient(90deg, #06b6d4, #2563eb, #7c3aed);
                    box-shadow: 0 4px 14px rgba(37, 99, 235, 0.45);
                }

                h2, h3 { font-weight: 700; }

                .stApp p, .stApp li, .stApp label,
                .stApp [data-testid="stMarkdownContainer"] {
                    color: var(--pg-text);
                }

                [data-testid="stCaptionContainer"], .stApp small {
                    color: var(--pg-muted) !important;
                }

                .stApp hr { border-color: var(--pg-line); }

                .pg-subtitle {
                    color: var(--pg-muted) !important;
                    margin-top: -8px;
                    margin-bottom: 24px;
                    font-size: 1.02rem;
                    padding: 2px 0 2px 14px;
                    border-left: 4px solid var(--pg-blue);
                }

                .pg-section {
                    color: var(--pg-ink);
                    font-size: 1.05rem;
                    font-weight: 700;
                    margin-top: 8px;
                    margin-bottom: 8px;
                }

                .pg-small { color: var(--pg-muted); font-size: 0.85rem; }

                .pg-risk {
                    padding: 5px 12px;
                    border-radius: 20px;
                    font-weight: 700;
                    font-size: 0.78rem;
                    display: inline-block;
                    letter-spacing: 0.04em;
                    text-transform: uppercase;
                }

                /* ---------- Sidebar (light, crisp, readable) ---------- */
                [data-testid="stSidebar"] {
                    background:
                        radial-gradient(380px 260px at 0% 0%, rgba(37, 99, 235, 0.10), transparent 70%),
                        linear-gradient(180deg, #ffffff 0%, #f4f8ff 100%);
                    border-right: 1px solid var(--pg-line);
                    box-shadow: 8px 0 40px rgba(37, 99, 235, 0.07);
                }

                [data-testid="stSidebar"]::before {
                    content: "";
                    position: absolute;
                    top: 0; left: 0; right: 0;
                    height: 4px;
                    background: linear-gradient(90deg, #06b6d4, #2563eb, #7c3aed);
                    z-index: 2;
                }

                [data-testid="stSidebar"] p,
                [data-testid="stSidebar"] label,
                [data-testid="stSidebar"] span,
                [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] {
                    color: var(--pg-text);
                }

                [data-testid="stSidebar"] hr { border-color: var(--pg-line); }

                [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
                    color: #8093b0 !important;
                    letter-spacing: 0.14em;
                    font-size: 0.7rem;
                    font-weight: 700;
                }

                /* API key field: dark text on white, always visible */
                [data-testid="stSidebar"] [data-testid="stWidgetLabel"],
                [data-testid="stSidebar"] [data-testid="stWidgetLabel"] p,
                [data-testid="stSidebar"] [data-testid="stWidgetLabel"] span {
                    color: var(--pg-ink) !important;
                    font-weight: 700;
                    font-size: 0.88rem;
                }

                [data-testid="stSidebar"] div[data-baseweb="input"],
                [data-testid="stSidebar"] div[data-baseweb="base-input"] {
                    background: #ffffff !important;
                    border: 1.5px solid var(--pg-line-strong) !important;
                    border-radius: 11px !important;
                    box-shadow: 0 2px 8px rgba(37, 99, 235, 0.06);
                }

                [data-testid="stSidebar"] input {
                    color: var(--pg-ink) !important;
                    -webkit-text-fill-color: var(--pg-ink) !important;
                    caret-color: var(--pg-blue);
                    background: transparent !important;
                    font-weight: 500;
                }

                [data-testid="stSidebar"] input::placeholder {
                    color: #8a9bb8 !important;
                    -webkit-text-fill-color: #8a9bb8 !important;
                    opacity: 1;
                }

                [data-testid="stSidebar"] [data-testid="stTextInput"] button,
                [data-testid="stSidebar"] [data-testid="stTextInput"] svg,
                [data-testid="stSidebar"] [data-testid="stTooltipIcon"] svg {
                    color: var(--pg-blue) !important;
                    fill: var(--pg-blue) !important;
                }

                /* nav menu */
                [data-testid="stSidebar"] [data-testid="stRadio"] label {
                    position: relative;
                    padding: 11px 14px;
                    margin-bottom: 5px;
                    border-radius: 12px;
                    border: 1px solid transparent;
                    transition: all 0.22s ease;
                    width: 100%;
                    cursor: pointer;
                }

                [data-testid="stSidebar"] [data-testid="stRadio"] label > div:first-child {
                    display: none;
                }

                [data-testid="stSidebar"] [data-testid="stRadio"] label p {
                    color: var(--pg-text);
                    font-weight: 500;
                }

                [data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
                    background: #eaf1ff;
                    border-color: #d3e1fb;
                    transform: translateX(4px);
                }

                [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
                    background: linear-gradient(90deg, #2563eb, #4f46e5);
                    border-color: transparent;
                    box-shadow: 0 8px 22px rgba(37, 99, 235, 0.35);
                }

                [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) p {
                    color: #ffffff !important;
                    font-weight: 700;
                }

                /* sidebar alert boxes (Gemini status) */
                [data-testid="stSidebar"] [data-testid="stAlert"],
                [data-testid="stSidebar"] [data-testid="stAlertContainer"] {
                    font-size: 0.84rem;
                    line-height: 1.45;
                }

                [data-testid="stSidebar"] .pg-sidebar-status,
                [data-testid="stSidebar"] .pg-sidebar-status * {
                    color: #065f46 !important;
                }

                [data-testid="stSidebar"] .pg-sidebar-status {
                    background: linear-gradient(90deg, #d1fae5, #ecfdf5);
                    border: 1px solid #6ee7b7;
                    border-radius: 12px;
                    padding: 11px 14px;
                    font-size: 0.86rem;
                    font-weight: 700;
                    margin: 10px 0;
                }

                [data-testid="stSidebar"] .pg-sidebar-status::before {
                    content: "";
                    display: inline-block;
                    width: 8px; height: 8px;
                    border-radius: 50%;
                    background: var(--pg-green);
                    margin-right: 8px;
                    animation: pg-pulse 1.8s infinite;
                }

                [data-testid="stSidebar"] div.stButton > button {
                    background: #ffffff !important;
                    color: var(--pg-ink) !important;
                    border: 1.5px solid var(--pg-line-strong) !important;
                    font-weight: 700;
                }

                [data-testid="stSidebar"] div.stButton > button:hover {
                    background: #eaf1ff !important;
                    color: #1d4ed8 !important;
                    border-color: #2563eb !important;
                    box-shadow: 0 6px 18px rgba(37, 99, 235, 0.18);
                }

                /* brand */
                .pg-brand {
                    padding: 8px 0 4px 0;
                    display: flex;
                    align-items: center;
                    gap: 13px;
                }

                .pg-brand-logo {
                    width: 48px; height: 48px;
                    border-radius: 14px;
                    display: flex; align-items: center; justify-content: center;
                    font-size: 25px;
                    background: linear-gradient(135deg, #06b6d4 0%, #2563eb 50%, #7c3aed 100%);
                    box-shadow: 0 10px 24px rgba(37, 99, 235, 0.40), inset 0 0 0 1px rgba(255, 255, 255, 0.4);
                }

                .pg-brand-name {
                    font-size: 25px;
                    font-weight: 800;
                    line-height: 1.05;
                    background: linear-gradient(95deg, #0f1f3d, #2563eb);
                    -webkit-background-clip: text;
                    background-clip: text;
                    -webkit-text-fill-color: transparent;
                }

                .pg-brand-tag {
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 9.5px;
                    letter-spacing: 1.6px;
                    color: #2563eb !important;
                    margin-top: 5px;
                    font-weight: 700;
                }

                /* ---------- KPI cards ---------- */
                div[data-testid="stMetric"] {
                    --acc: #2563eb; --acc-rgb: 37, 99, 235;
                    position: relative;
                    overflow: hidden;
                    background:
                        linear-gradient(160deg, rgba(var(--acc-rgb), 0.10) 0%, #ffffff 58%);
                    border: 1px solid rgba(var(--acc-rgb), 0.22);
                    padding: 24px 24px 22px 24px;
                    min-height: 128px;
                    border-radius: 18px;
                    box-shadow: var(--pg-shadow);
                    transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
                }

                [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:nth-child(1) div[data-testid="stMetric"],
                [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-child(1) div[data-testid="stMetric"] { --acc: #2563eb; --acc-rgb: 37, 99, 235; }
                [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:nth-child(2) div[data-testid="stMetric"],
                [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-child(2) div[data-testid="stMetric"] { --acc: #ef4444; --acc-rgb: 239, 68, 68; }
                [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:nth-child(3) div[data-testid="stMetric"],
                [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-child(3) div[data-testid="stMetric"] { --acc: #f59e0b; --acc-rgb: 245, 158, 11; }
                [data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:nth-child(4) div[data-testid="stMetric"],
                [data-testid="stHorizontalBlock"] > [data-testid="column"]:nth-child(4) div[data-testid="stMetric"] { --acc: #10b981; --acc-rgb: 16, 185, 129; }

                div[data-testid="stMetric"]::before {
                    content: "";
                    position: absolute;
                    top: 0; left: 0; right: 0;
                    height: 5px;
                    background: linear-gradient(90deg, var(--acc), rgba(var(--acc-rgb), 0.25));
                }

                div[data-testid="stMetric"]::after {
                    content: "";
                    position: absolute;
                    top: -50px; right: -50px;
                    width: 150px; height: 150px;
                    background: radial-gradient(circle, rgba(var(--acc-rgb), 0.22), transparent 70%);
                }

                div[data-testid="stMetric"]:hover {
                    transform: translateY(-6px);
                    border-color: rgba(var(--acc-rgb), 0.55);
                    box-shadow: 0 18px 44px rgba(var(--acc-rgb), 0.22), 0 2px 4px rgba(15, 31, 61, 0.05);
                }

                div[data-testid="stMetricLabel"] p {
                    color: var(--acc) !important;
                    font-size: 0.76rem;
                    font-weight: 700;
                    text-transform: uppercase;
                    letter-spacing: 0.1em;
                }

                div[data-testid="stMetricValue"] {
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 2.6rem !important;
                    font-weight: 700;
                    color: var(--pg-ink);
                }

                /* ---------- Cards ---------- */
                div[data-testid="stVerticalBlockBorderWrapper"] {
                    background: linear-gradient(180deg, #ffffff 0%, #fbfdff 100%);
                    border: 1px solid var(--pg-line) !important;
                    border-radius: 18px;
                    box-shadow: var(--pg-shadow);
                    transition: transform 0.25s ease, box-shadow 0.25s ease, border-color 0.25s ease;
                }

                div[data-testid="stVerticalBlockBorderWrapper"]:hover {
                    border-color: #bcd0f3 !important;
                    box-shadow: var(--pg-shadow-hover);
                    transform: translateY(-2px);
                }

                div[data-testid="stForm"] {
                    position: relative;
                    background: linear-gradient(160deg, #f5f8ff 0%, #ffffff 40%);
                    border: 1px solid var(--pg-line-strong);
                    border-radius: 18px;
                    padding: 26px;
                    box-shadow: var(--pg-shadow);
                }

                div[data-testid="stForm"]::before {
                    content: "";
                    position: absolute;
                    top: 0; left: 26px; right: 26px;
                    height: 3px;
                    border-radius: 0 0 6px 6px;
                    background: linear-gradient(90deg, #06b6d4, #2563eb, #7c3aed);
                }

                div[data-testid="stExpander"] {
                    background: #ffffff;
                    border-radius: 14px;
                    border: 1px solid var(--pg-line);
                    border-left: 4px solid var(--pg-blue);
                    box-shadow: var(--pg-shadow);
                    overflow: hidden;
                }

                div[data-testid="stExpander"] summary:hover { background: #f1f6ff; }
                div[data-testid="stExpander"] summary p { font-weight: 600; color: var(--pg-ink); }

                /* ---------- Inputs (main area) ---------- */
                div[data-baseweb="input"],
                div[data-baseweb="base-input"],
                div[data-baseweb="textarea"],
                div[data-baseweb="select"] > div {
                    background: #ffffff !important;
                    border-color: var(--pg-line-strong) !important;
                    border-radius: 11px !important;
                    transition: all 0.2s ease;
                }

                div[data-baseweb="input"]:focus-within,
                div[data-baseweb="base-input"]:focus-within,
                div[data-baseweb="textarea"]:focus-within,
                div[data-baseweb="select"]:focus-within > div {
                    border-color: var(--pg-blue) !important;
                    box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.14);
                }

                .stApp input, .stApp textarea {
                    color: var(--pg-ink) !important;
                    -webkit-text-fill-color: var(--pg-ink) !important;
                    background: transparent !important;
                }

                .stApp input::placeholder, .stApp textarea::placeholder {
                    color: #8a9bb8 !important;
                    -webkit-text-fill-color: #8a9bb8 !important;
                    opacity: 1;
                }

                div[data-baseweb="select"] * { color: var(--pg-ink) !important; }

                ul[data-baseweb="menu"], div[data-baseweb="popover"] > div {
                    background: #ffffff !important;
                    border: 1px solid var(--pg-line-strong);
                    border-radius: 12px;
                    box-shadow: 0 16px 40px rgba(15, 31, 61, 0.15);
                }

                li[role="option"]:hover { background: #eaf1ff !important; }

                [data-testid="stFileUploaderDropzone"] {
                    background: linear-gradient(160deg, #f3f7ff, #ffffff);
                    border: 2px dashed #a9c0ee;
                    border-radius: 16px;
                    transition: all 0.25s ease;
                }

                [data-testid="stFileUploaderDropzone"]:hover {
                    border-color: var(--pg-blue);
                    background: #eaf1ff;
                    box-shadow: 0 10px 28px rgba(37, 99, 235, 0.14);
                }

                /* ---------- Buttons ---------- */
                div.stButton > button,
                div.stFormSubmitButton > button,
                div.stDownloadButton > button {
                    position: relative;
                    overflow: hidden;
                    border-radius: 11px;
                    font-weight: 600;
                    min-height: 44px;
                    background: #ffffff;
                    color: var(--pg-ink);
                    border: 1.5px solid var(--pg-line-strong);
                    transition: all 0.22s ease;
                }

                div.stButton > button:hover,
                div.stFormSubmitButton > button:hover,
                div.stDownloadButton > button:hover {
                    border-color: var(--pg-blue);
                    color: var(--pg-blue);
                    transform: translateY(-2px);
                    box-shadow: 0 10px 24px rgba(37, 99, 235, 0.18);
                }

                div.stButton > button::after,
                div.stFormSubmitButton > button::after {
                    content: "";
                    position: absolute;
                    top: 0; left: -80%;
                    width: 50%; height: 100%;
                    background: linear-gradient(100deg, transparent, rgba(255, 255, 255, 0.55), transparent);
                    transform: skewX(-20deg);
                    transition: left 0.6s ease;
                }

                div.stButton > button:hover::after,
                div.stFormSubmitButton > button:hover::after { left: 130%; }

                div.stButton > button[kind="primary"],
                div.stFormSubmitButton > button[kind="primary"] {
                    min-height: 48px;
                    font-size: 1rem;
                    font-weight: 700;
                    letter-spacing: 0.02em;
                    color: #ffffff;
                    border: none;
                    background: linear-gradient(120deg, #2563eb 0%, #4f46e5 55%, #7c3aed 100%);
                    box-shadow: 0 10px 26px rgba(79, 70, 229, 0.40);
                }

                div.stButton > button[kind="primary"]:hover,
                div.stFormSubmitButton > button[kind="primary"]:hover {
                    color: #ffffff;
                    filter: brightness(1.08);
                    box-shadow: 0 14px 34px rgba(79, 70, 229, 0.55);
                }

                /* ---------- Progress (static bars, length = proportion of the count) ---------- */
                /* Track: empty outline. A 0-count bar shows only this outline. */
                div[data-testid="stProgress"] div[role="progressbar"] > div {
                    background: #f4f8ff !important;
                    background-image: none !important;
                    border: 1.5px solid #bcd0f3;
                    border-radius: 99px;
                    height: 14px !important;
                    overflow: hidden;
                    box-shadow: inset 0 1px 3px rgba(15, 31, 61, 0.08);
                    animation: none !important;
                }

                /* Fill: only as long as the value, so 4 is shorter than 5 and 0 is empty. */
                div[data-testid="stProgress"] div[role="progressbar"] > div > div {
                    background-color: #2563eb !important;
                    background-image: linear-gradient(90deg, #06b6d4, #2563eb, #7c3aed) !important;
                    border-radius: 99px;
                    animation: none !important;
                    box-shadow: none;
                }

                div[data-testid="stProgress"] div[role="progressbar"][aria-valuenow="0"] > div > div {
                    display: none !important;
                }

                /* ---------- Alerts: tinted, always readable ---------- */
                [data-testid="stAlert"],
                [data-testid="stAlertContainer"],
                div[data-baseweb="notification"],
                div[role="alert"] {
                    background: #f3f7ff !important;
                    border: 1px solid #cfdcf5;
                    border-radius: 13px !important;
                    box-shadow: 0 4px 14px rgba(37, 99, 235, 0.07);
                }

                [data-testid="stAlert"] *,
                [data-testid="stAlertContainer"] *,
                div[data-baseweb="notification"] *,
                div[role="alert"] * {
                    color: #1b2a4a !important;
                    -webkit-text-fill-color: #1b2a4a !important;
                }

                [data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]),
                div[data-baseweb="notification"][kind="positive"] { background: #ecfdf5 !important; border-color: #6ee7b7; }
                [data-testid="stAlertContainer"]:has([data-testid="stAlertContentWarning"]),
                div[data-baseweb="notification"][kind="warning"]  { background: #fffbeb !important; border-color: #fcd34d; }
                [data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]),
                div[data-baseweb="notification"][kind="negative"] { background: #fef2f2 !important; border-color: #fca5a5; }
                [data-testid="stAlertContainer"]:has([data-testid="stAlertContentInfo"]),
                div[data-baseweb="notification"][kind="info"]     { background: #eff6ff !important; border-color: #93c5fd; }

                /* ---------- Tabs, tables, misc ---------- */
                [data-baseweb="tab-list"] {
                    gap: 6px;
                    background: #eaf0fb;
                    padding: 5px;
                    border-radius: 13px;
                }

                button[data-baseweb="tab"] { color: var(--pg-muted); font-weight: 600; }

                button[data-baseweb="tab"][aria-selected="true"] {
                    color: var(--pg-blue);
                    background: #ffffff;
                    border-radius: 9px;
                    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.15);
                }

                div[data-baseweb="tab-highlight"] { background: transparent; }

                [data-testid="stDataFrame"], [data-testid="stTable"] {
                    border: 1px solid var(--pg-line);
                    border-radius: 14px;
                    overflow: hidden;
                    box-shadow: var(--pg-shadow);
                }

                div[data-testid="stTooltipContent"],
                div[data-baseweb="tooltip"] > div {
                    background: #ffffff !important;
                    color: var(--pg-ink) !important;
                    border: 1px solid var(--pg-line-strong);
                    border-radius: 10px;
                    box-shadow: 0 12px 30px rgba(15, 31, 61, 0.15);
                }

                code {
                    font-family: 'JetBrains Mono', monospace;
                    background: #eaf1ff !important;
                    color: #1d4ed8 !important;
                    border-radius: 6px;
                    padding: 2px 6px;
                }

                ::selection { background: rgba(37, 99, 235, 0.22); }

                ::-webkit-scrollbar { width: 10px; height: 10px; }
                ::-webkit-scrollbar-track { background: #eef3fc; }
                ::-webkit-scrollbar-thumb {
                    background: linear-gradient(180deg, #60a5fa, #818cf8);
                    border-radius: 10px;
                }

                [data-testid="stVerticalBlock"] > [data-testid="stElementContainer"],
                [data-testid="stVerticalBlock"] > div[data-testid="element-container"] {
                    animation: pg-rise 0.5s ease both;
                }

                /* ---------- Buttons: force blue states (no red hover/focus/active) ---------- */
                .stApp button p, .stApp button span { color: inherit !important; }

                button[data-testid="stBaseButton-secondary"],
                button[data-testid="stBaseButton-secondaryFormSubmit"],
                button[kind="secondary"],
                button[kind="secondaryFormSubmit"] {
                    background: #ffffff !important;
                    color: #0f1f3d !important;
                    border: 1.5px solid #c9d6ec !important;
                }

                button[data-testid="stBaseButton-secondary"]:hover,
                button[data-testid="stBaseButton-secondary"]:focus,
                button[data-testid="stBaseButton-secondary"]:focus:not(:active),
                button[data-testid="stBaseButton-secondary"]:active,
                button[data-testid="stBaseButton-secondaryFormSubmit"]:hover,
                button[data-testid="stBaseButton-secondaryFormSubmit"]:focus,
                button[data-testid="stBaseButton-secondaryFormSubmit"]:focus:not(:active),
                button[data-testid="stBaseButton-secondaryFormSubmit"]:active,
                button[kind="secondary"]:hover,
                button[kind="secondary"]:focus,
                button[kind="secondary"]:focus:not(:active),
                button[kind="secondary"]:active,
                button[kind="secondaryFormSubmit"]:hover,
                button[kind="secondaryFormSubmit"]:focus,
                button[kind="secondaryFormSubmit"]:focus:not(:active),
                button[kind="secondaryFormSubmit"]:active {
                    background: #eaf1ff !important;
                    color: #1d4ed8 !important;
                    border-color: #2563eb !important;
                    box-shadow: 0 8px 22px rgba(37, 99, 235, 0.20) !important;
                    outline: none !important;
                }

                button[data-testid="stBaseButton-primary"],
                button[data-testid="stBaseButton-primaryFormSubmit"],
                button[kind="primary"],
                button[kind="primaryFormSubmit"],
                button[data-testid="stBaseButton-primary"]:hover,
                button[data-testid="stBaseButton-primary"]:focus,
                button[data-testid="stBaseButton-primary"]:focus:not(:active),
                button[data-testid="stBaseButton-primary"]:active,
                button[data-testid="stBaseButton-primaryFormSubmit"]:hover,
                button[data-testid="stBaseButton-primaryFormSubmit"]:focus,
                button[data-testid="stBaseButton-primaryFormSubmit"]:focus:not(:active),
                button[data-testid="stBaseButton-primaryFormSubmit"]:active,
                button[kind="primary"]:hover,
                button[kind="primary"]:focus,
                button[kind="primary"]:focus:not(:active),
                button[kind="primary"]:active,
                button[kind="primaryFormSubmit"]:hover,
                button[kind="primaryFormSubmit"]:focus,
                button[kind="primaryFormSubmit"]:focus:not(:active),
                button[kind="primaryFormSubmit"]:active {
                    background-color: #2563eb !important;
                    background-image: linear-gradient(120deg, #2563eb 0%, #4f46e5 55%, #7c3aed 100%) !important;
                    color: #ffffff !important;
                    border: none !important;
                    outline: none !important;
                }

                button[data-testid="stBaseButton-primary"]:hover,
                button[data-testid="stBaseButton-primaryFormSubmit"]:hover,
                button[kind="primary"]:hover,
                button[kind="primaryFormSubmit"]:hover {
                    filter: brightness(1.08);
                    box-shadow: 0 14px 34px rgba(79, 70, 229, 0.50) !important;
                }

                button[data-testid="stBaseButton-secondary"]:focus-visible,
                button[data-testid="stBaseButton-primary"]:focus-visible,
                button[data-testid="stBaseButton-secondaryFormSubmit"]:focus-visible,
                button[data-testid="stBaseButton-primaryFormSubmit"]:focus-visible {
                    box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.25) !important;
                }

                /* ---------- KPI values: never truncate long text (e.g. "Urgent Security Review") ---------- */
                div[data-testid="stMetricValue"],
                div[data-testid="stMetricValue"] > div,
                div[data-testid="stMetricValue"] * {
                    white-space: normal !important;
                    overflow: visible !important;
                    text-overflow: clip !important;
                    overflow-wrap: anywhere;
                    word-break: normal;
                    line-height: 1.2 !important;
                }

                div[data-testid="stMetricValue"] {
                    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif !important;
                    font-size: clamp(1.45rem, 2.1vw, 2.15rem) !important;
                    font-weight: 800 !important;
                    letter-spacing: -0.02em;
                    color: #0f1f3d !important;
                }

                div[data-testid="stMetricValue"] * {
                    font-size: inherit !important;
                    font-family: inherit !important;
                    font-weight: inherit !important;
                    color: inherit !important;
                }

                div[data-testid="stMetricLabel"],
                div[data-testid="stMetricLabel"] * {
                    white-space: normal !important;
                    overflow: visible !important;
                    text-overflow: clip !important;
                }

                div[data-testid="stMetric"] {
                    min-height: 128px;
                    height: auto;
                }
            </style>
            """,
            unsafe_allow_html=True,
        )

    def _render_sidebar(self):
        with st.sidebar:
            st.markdown(
                """
                <div class="pg-brand">
                    <div class="pg-brand-logo">🛡️</div>
                    <div>
                        <div class="pg-brand-name">PhishGuard</div>
                        <div class="pg-brand-tag">AI-POWERED EMAIL SECURITY</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.divider()
            st.caption("WORKSPACE")

            choice = st.radio(
                "Navigation",
                self.MENU_OPTIONS,
                key="main_menu_choice",
                label_visibility="collapsed",
                format_func=lambda item: {
                    "Dashboard": "▦  Dashboard",
                    "Submit Report": "✉️  Submit Report",
                    "Keyword Checker": "⌕  Keyword Checker",
                    "Find a Report": "▤  Find a Report",
                    "IT Security Review": "🛡️  IT Security Review",
                }.get(item, item),
            )

            st.divider()
            st.caption("PHISHGUARD v1.0")
            st.caption("Intelligent Email Threat Detection")

            if st.session_state.get("it_authenticated", False):
                st.markdown(
                    '<div class="pg-sidebar-status">● IT Security session active</div>',
                    unsafe_allow_html=True,
                )
                if st.button(
                    "Log out of IT Security",
                    key="it_security_logout",
                    use_container_width=True,
                ):
                    st.session_state["it_authenticated"] = False
                    st.rerun()

        return choice

    # --------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------

    def _render_dashboard(self):
        records = self.data_manager.load_records()

        st.title("Security Dashboard")
        st.markdown(
            '<div class="pg-subtitle">Overview of submitted email reports and detected threats.</div>',
            unsafe_allow_html=True,
        )

        total_reports = len(records)
        critical_reports = 0
        pending_reports = 0
        resolved_reports = 0
        threat_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Unknown": 0,
        }

        for record in records:
            ai_result = record.get("ai_analysis") or {}
            threat = str(
                ai_result.get("threat_level")
                or record.get("threat_level")
                or "Unknown"
            ).title()

            if threat not in threat_counts:
                threat_counts[threat] = 0
            threat_counts[threat] += 1

            if threat.lower() == "critical":
                critical_reports += 1

            status = str(record.get("review_status", "")).lower()
            stage = str(record.get("review_stage", "")).lower()

            if stage != "closed" and status not in (
                "resolved",
                "false positive",
                "done",
                "closed",
            ):
                pending_reports += 1

            if stage == "closed" or status in (
                "resolved",
                "false positive",
                "done",
                "closed",
            ):
                resolved_reports += 1

        st.subheader("Security Overview")
        metric_columns = st.columns(4)

        with metric_columns[0]:
            st.metric("Total Reports", total_reports, help="All reports saved in PhishGuard.")
        with metric_columns[1]:
            st.metric("Critical Threats", critical_reports, help="Reports assessed as critical.")
        with metric_columns[2]:
            st.metric("Pending Reviews", pending_reports, help="Reports not yet finalized.")
        with metric_columns[3]:
            st.metric("Resolved Reports", resolved_reports, help="Reports with a closed or resolved status.")

        st.write("")
        left_column, right_column = st.columns([1.1, 1])

        with left_column:
            with st.container(border=True):
                st.subheader("Threat Distribution")
                highest_threat_count = max(threat_counts.values(), default=1)
                if any(threat_counts.values()):
                    for threat_level, count in threat_counts.items():
                        st.write(f"**{threat_level}** — {count} report(s)")
                        st.progress(min(count / max(total_reports, 1), 1.0))
                else:
                    st.info("No threat-level data is available yet.")

        with right_column:
            with st.container(border=True):
                st.subheader("Report Status")
                status_counts = {}
                for record in records:
                    status = str(record.get("review_status", "Unknown")).title()
                    status_counts[status] = status_counts.get(status, 0) + 1

                if status_counts:
                    highest_status_count = max(status_counts.values(), default=1)
                    for status, count in status_counts.items():
                        st.write(f"**{status}** — {count} report(s)")
                        st.progress(min(count / max(total_reports, 1), 1.0))
                else:
                    st.info("No report status data is available yet.")

        st.subheader("Recent Reports")
        if not records:
            st.info("No reports have been submitted yet. Select **Submit Report** to get started.")
            return

        recent_records = list(reversed(records[-8:]))
        for record in recent_records:
            ai_result = record.get("ai_analysis") or {}
            report = record.get("report") or {}
            with st.container(border=True):
                report_columns = st.columns([1.0, 1.5, 1.0, 1.2, 1.0])
                report_columns[0].markdown(f"**{record.get('report_id', 'Unknown')}**")
                report_columns[1].write(report.get("sender_email") or report.get("sender_name") or "Not provided")
                report_columns[2].write(str(ai_result.get("threat_level", "Unknown")).title())
                report_columns[3].write(str(record.get("review_status", "Unknown")).title())
                report_columns[4].write(f"Risk: {record.get('risk_score', 0)}/100")

        st.caption("Dashboard figures are calculated from the reports currently stored by PhishGuard.")

    # --------------------------------------------------
    # REPORT SUBMISSION
    # --------------------------------------------------

    def _render_report_submission(self):
        st.title("Submit Email Report")
        st.markdown(
            '<div class="pg-subtitle">Submit a suspicious email for AI-powered phishing analysis.</div>',
            unsafe_allow_html=True,
        )

        input_method = st.radio(
            "How would you like to provide the email?",
            ("Enter manually", "Upload an image for OCR"),
            horizontal=True,
            key="report_input_method",
        )

        extracted = {}

        if input_method == "Upload an image for OCR":
            with st.container(border=True):
                st.subheader("Upload email screenshot")
                st.caption(
                    "The image is processed locally with Tesseract and is not uploaded "
                    "to the AI service. Review the extracted text before analysis."
                )

                if not self.ocr_extractor.is_available():
                    st.error(
                        "Local OCR is unavailable. Install Tesseract OCR and ensure "
                        "its executable is on PATH, then restart Streamlit."
                    )
                    return

                image = st.file_uploader(
                    "Email screenshot (PNG, JPEG, or WEBP; maximum 10 MB)",
                    type=("png", "jpg", "jpeg", "webp"),
                    key="email_screenshot",
                )

                if image is None:
                    st.info("Upload a screenshot to extract its email text.")
                    return

                image_bytes = image.getvalue()
                if not image_bytes or len(image_bytes) > 10 * 1024 * 1024:
                    st.error("The image must be between 1 byte and 10 MB.")
                    return

                image_key = f"{image.name}:{len(image_bytes)}:{hash(image_bytes)}"
                if st.session_state.get("ocr_image_key") != image_key:
                    st.session_state.pop("ocr_report_fields", None)
                    st.session_state["ocr_image_key"] = image_key

                if "ocr_report_fields" not in st.session_state:
                    if st.button("Extract email text from image", type="primary"):
                        try:
                            extracted = self._extract_uploaded_image(image.name, image_bytes)
                            st.session_state["ocr_report_fields"] = extracted
                            st.rerun()
                        except (ValueError, ExtractionError) as error:
                            st.error(f"Could not read the screenshot: {error}")
                    return

                extracted = st.session_state["ocr_report_fields"]
                st.success("Text extracted. Check and edit the fields below.")

        st.subheader("Email information")
        with st.form("report_submission", enter_to_submit=False):
            sender_column, name_column = st.columns(2)
            with sender_column:
                sender_email = st.text_input(
                    "Sender email",
                    value=extracted.get("sender_email", ""),
                    placeholder="sender@example.com",
                )
            with name_column:
                sender_name = st.text_input(
                    "Sender display name",
                    value=extracted.get("sender_name", ""),
                    placeholder="Displayed sender name",
                )

            subject = st.text_input(
                "Email subject",
                value=extracted.get("subject", ""),
                placeholder="Enter the email subject",
            )

            st.markdown("**Email content**")
            body = st.text_area(
                "Email message",
                value=extracted.get("body", ""),
                height=220,
                placeholder="Paste the suspicious email content here...",
                label_visibility="collapsed",
            )

            urls = st.text_input(
                "URLs found (comma-separated)",
                value=", ".join(extracted.get("urls", [])),
                placeholder="https://example.com, https://another-example.com",
            )

            st.divider()
            st.markdown("**Have you interacted with this email?**")
            action_column_1, action_column_2, action_column_3 = st.columns(3)
            with action_column_1:
                clicked_link = st.checkbox("Clicked a link")
            with action_column_2:
                opened_attachment = st.checkbox("Opened an attachment")
            with action_column_3:
                entered_information = st.checkbox("Entered personal/account information")

            submitted = st.form_submit_button(
                "🛡️ Analyze and Submit Report",
                type="primary",
                use_container_width=True,
            )

        if not submitted:
            return

        if not any((sender_email.strip(), subject.strip(), body.strip())):
            st.error("Enter at least an email address, subject, or message.")
            return

        report = {
            "viewed": True,
            "sender_email": sender_email.strip(),
            "sender_name": sender_name.strip(),
            "subject": subject.strip(),
            "body": body.strip(),
            "urls": [url.strip() for url in urls.split(",") if url.strip()],
            "attachments": [],
            "input_method": "screenshot OCR" if input_method == "Upload an image for OCR" else "typed",
            "actions_taken": {
                "clicked_link": clicked_link,
                "opened_attachment": opened_attachment,
                "entered_information": entered_information,
            },
        }

        with st.spinner("Analyzing the report..."):
            ai_result, ai_error = self.analyzer.analyze(report)

        records = self.data_manager.load_records()
        report_id = self.logic_manager.next_report_id(records)
        record = self.logic_manager.build_final_record(
            report_id, report, ai_result, ai_error
        )
        outcome = self.data_manager.add_record(record)
        self._show_store_warnings()

        if outcome.get("duplicate"):
            st.warning("This report has already been submitted.")
            return

        if not outcome.get("saved"):
            st.error("The report could not be saved.")
            return

        st.success(f"Report submitted successfully. Your report ID is {report_id}.")
        self._show_record(record)

        if input_method == "Upload an image for OCR":
            st.session_state.pop("ocr_report_fields", None)
            st.session_state.pop("ocr_image_key", None)

    def _extract_uploaded_image(self, filename, image_bytes):
        suffix = os.path.splitext(filename)[1].lower()
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as image_file:
                image_file.write(image_bytes)
                temp_path = image_file.name
            image_info = self.attachment_reader.inspect(temp_path, image_only=True)
            return self.ocr_extractor.extract(image_info["path"])
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    # --------------------------------------------------
    # KEYWORD CHECKER
    # --------------------------------------------------

    def _render_keyword_checker(self):
        st.title("Keyword Checker")
        st.markdown(
            '<div class="pg-subtitle">Quickly scan suspicious email content for phishing-related indicators.</div>',
            unsafe_allow_html=True,
        )

        with st.form("keyword_scan", enter_to_submit=False):
            text = st.text_area(
                "Paste suspicious email text",
                height=240,
                placeholder="Paste the email content you want to inspect...",
            )
            deep_scan = st.checkbox("Also run the full AI analysis")
            submitted = st.form_submit_button("Scan Email", type="primary")

        if not submitted:
            return

        if not text.strip():
            st.error("Enter some text to scan.")
            return

        result = self.keyword_checker.scan(text)

        st.subheader("Offline Keyword Scan")
        result_column_1, result_column_2 = st.columns(2)
        with result_column_1:
            st.metric("Scan Level", str(result.get("level", "Unknown")).title())
        with result_column_2:
            st.metric("Keyword Score", result.get("score", 0))

        found_any = False
        for category, matches in result.get("found", {}).items():
            if matches:
                found_any = True
                with st.container(border=True):
                    st.markdown(f"**{category.replace('_', ' ').title()}**")
                    st.write(", ".join(matches))

        if not found_any:
            st.info("No configured suspicious keywords were detected.")

        if deep_scan:
            with st.spinner("Running AI analysis..."):
                ai_result, error = self.analyzer.analyze(
                    {
                        "body": text,
                        "subject": "",
                        "sender_name": "",
                        "sender_email": "",
                        "viewed": True,
                    }
                )

            if ai_result:
                self._show_ai_result(ai_result)
            else:
                st.error(f"AI analysis failed: {error}")

    # --------------------------------------------------
    # IT SECURITY AUTHENTICATION AND REVIEW
    # --------------------------------------------------

    def _it_authentication_gate(self):
        if st.session_state.get("it_authenticated", False):
            return True

        st.warning("IT Security access requires authentication.")

        with st.form("it_authentication", enter_to_submit=False):
            password = st.text_input("IT password", type="password")
            submitted = st.form_submit_button("Log in", type="primary")

        if submitted:
            if self.logic_manager.verify_it_password(password):
                st.session_state["it_authenticated"] = True
                st.rerun()
            else:
                st.error("Incorrect password.")

        return False

    def _render_it_review(self):
        st.title("IT Security Review")
        st.markdown(
            '<div class="pg-subtitle">Review, investigate and manage submitted phishing reports.</div>',
            unsafe_allow_html=True,
        )

        if not self._it_authentication_gate():
            return

        records = self.logic_manager.sort_records_by_priority(
            self.data_manager.load_records()
        )

        if not records:
            st.info("No reports have been submitted.")
            return

        pending_count = sum(
            1 for record in records
            if record.get("review_stage") != "closed"
        )
        closed_count = len(records) - pending_count

        metric_1, metric_2, metric_3 = st.columns(3)
        metric_1.metric("Total Reports", len(records))
        metric_2.metric("Awaiting Review", pending_count)
        metric_3.metric("Finalized", closed_count)

        st.divider()
        st.subheader("Investigation Queue")

        report_ids = [record["report_id"] for record in records]
        report_id = st.selectbox(
            "Select a report to investigate",
            report_ids,
            key="review_report_id",
        )

        record_index = self.logic_manager.find_record_index(records, report_id)
        record = records[record_index]

        with st.container(border=True):
            self._show_record(record)

        if record.get("review_stage") == "closed":
            st.info("This report is finalized and locked.")
            return

        self._render_review_form(records, record_index, record)

    def _render_review_form(self, records, record_index, record):
        st.subheader("Investigation Review")
        is_second_review = record.get("review_stage") == "awaiting_second_review"

        with st.form(f"review_{record['report_id']}", enter_to_submit=False):
            reviewer = st.text_input(
                "Reviewer name",
                value=record.get("assigned_reviewer", "") if is_second_review else "",
            )

            if is_second_review:
                st.info("This report is awaiting its second review.")
                decision = st.radio("Decision", ("Approve", "Reject"))
                rejection_reason = (
                    st.text_area("Reason for rejection")
                    if decision == "Reject"
                    else ""
                )

                submitted = st.form_submit_button(
                    "Save Second Review",
                    type="primary",
                )

                updates = {
                    "review_action": "second",
                    "reviewer": reviewer,
                    "approval_decision": decision.lower(),
                    "rejection_reason": rejection_reason,
                }

            else:
                outcome = st.selectbox(
                    "Investigation outcome",
                    ("Resolved (real scam)", "False Positive (not a scam)"),
                )
                risk_level = st.selectbox("Risk level", ("Low", "High"))
                assigned_reviewer = st.text_input("Assign the next reviewer")
                note = st.text_area("Review note (optional)")

                submitted = st.form_submit_button(
                    "Save First Review",
                    type="primary",
                )

                updates = {
                    "review_action": "first",
                    "reviewer": reviewer,
                    "report_outcome": outcome,
                    "risk_level": risk_level,
                    "assigned_reviewer": assigned_reviewer,
                    "note": note,
                }

        if not submitted:
            return

        updated, errors = self.logic_manager.apply_review_update(record, updates)

        if errors:
            for error in errors:
                st.error(error)
            return

        records[record_index] = updated

        if not self.data_manager.save_records(records):
            self._show_store_warnings()
            st.error("The review could not be saved.")
            return

        st.success("Review saved successfully.")
        st.rerun()

    # --------------------------------------------------
    # REPORT SEARCH
    # --------------------------------------------------

    def _render_report_search(self):
        st.title("Find a Report")
        st.markdown(
            '<div class="pg-subtitle">Search submitted reports by ID, sender, subject or email content.</div>',
            unsafe_allow_html=True,
        )

        if not self._it_authentication_gate():
            return

        records = self.data_manager.load_records()

        if not records:
            st.info("No reports have been submitted.")
            return

        query = st.text_input(
            "Search reports",
            placeholder="e.g. PG-0010, sender@example.com, account suspension...",
        )

        found = (
            self.data_manager.search_records(records, query)
            if query.strip()
            else records
        )

        if not found:
            st.warning("No matching reports found.")
            return

        st.caption(f"{len(found)} matching report(s)")

        report_id = st.selectbox(
            "Matching reports",
            [record["report_id"] for record in found],
            key="search_report_id",
        )

        selected = self.data_manager.find_record(records, report_id)

        if selected:
            with st.container(border=True):
                self._show_record(selected)

    # --------------------------------------------------
    # REUSABLE DISPLAY COMPONENTS
    # --------------------------------------------------

    @staticmethod
    def _show_ai_result(result):
        st.subheader("AI Threat Assessment")

        threat = str(result.get("threat_level", "unknown")).title()
        confidence = result.get("confidence", 0)
        if not isinstance(confidence, (int, float)):
            confidence = 0

        if confidence > 1:
            confidence = confidence / 100

        confidence = max(0, min(confidence, 1))

        threat_column, confidence_column = st.columns(2)

        with threat_column:
            st.metric("Threat Level", threat)

        with confidence_column:
            st.metric("AI Confidence", f"{confidence:.0%}")

        mode = result.get("analysis_mode", "unknown")
        api_error = result.get("api_error")
        if mode == "Gemini AI":
            st.success("API status: working. Analysed by Gemini AI.")
        elif api_error and api_error != "API key not set":
            st.warning(f"API status: not working ({api_error}). Offline rules were used.")
        else:
            st.info("API status: not used (no API key). Offline rules were used.")
        st.write(f"**Analysis mode:** {mode}")

        st.write(f"**Analysis mode:** {result.get('analysis_mode', 'unknown')}")
        st.write(f"**Attack Type:** {result.get('attack_type', 'Unknown')}")
        st.write(f"**Explanation:** {result.get('explanation', 'No explanation provided.')}")
        st.write(f"**Recommended Action:** {result.get('recommended_action', 'No recommendation provided.')}")

        with st.expander("View full AI assessment data"):
            st.json(result)

    def _show_record(self, record):
        report_id = record.get("report_id", "Unknown")
        priority = record.get("priority", "Unknown")
        review_status = record.get("review_status", "Unknown")
        risk_score = record.get("risk_score", 0)

        st.markdown(f"### Report {report_id}")

        col_1, col_2, col_3 = st.columns(3)
        col_1.metric("Priority", str(priority).title())
        col_2.metric("Review Status", str(review_status).title())
        col_3.metric("Risk Score", f"{risk_score}/100")

        if record.get("ai_analysis"):
            self._show_ai_result(record["ai_analysis"])
        elif record.get("ai_error"):
            st.warning(f"AI result unavailable: {record['ai_error']}")

        report = record.get("report") or {}

        with st.expander("Email and submission details", expanded=True):
            sender_column, name_column = st.columns(2)
            sender_column.write(f"**Sender email:** {report.get('sender_email') or 'Not provided'}")
            name_column.write(f"**Sender name:** {report.get('sender_name') or 'Not provided'}")
            st.write(f"**Subject:** {report.get('subject') or 'Not provided'}")
            st.write("**Email message**")
            st.text(report.get("body") or "No email body provided.")

            urls = report.get("urls") or []
            if urls:
                st.write("**URLs found:**")
                for url in urls:
                    st.write(f"- {url}")

            actions = report.get("actions_taken") or {}
            st.write("**User actions:**")
            st.write(f"- Clicked link: {'Yes' if actions.get('clicked_link', False) else 'No'}")
            st.write(f"- Opened attachment: {'Yes' if actions.get('opened_attachment', False) else 'No'}")
            st.write(f"- Entered information: {'Yes' if actions.get('entered_information', False) else 'No'}")

        with st.expander("View technical report data"):
            st.json(record)

    def _show_store_warnings(self):
        for warning in self.data_manager.take_warnings():
            st.warning(warning)


if __name__ == "__main__":
    PhishGuardWebApp().render()
