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
                .stApp {
                    background: #f5f7fb;
                }

                [data-testid="stSidebar"] {
                    background: #14243b;
                    border-right: 1px solid #263b58;
                }

                [data-testid="stSidebar"] * {
                    color: #edf3fb;
                }

                [data-testid="stSidebar"] [data-testid="stRadio"] label {
                    padding: 7px 10px;
                    border-radius: 8px;
                }

                [data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
                    background: #263d5b;
                }

                /* Keep the IT session indicator readable against its light background. */
                [data-testid="stSidebar"] .pg-sidebar-status,
                [data-testid="stSidebar"] .pg-sidebar-status * {
                    color: #065f46 !important;
                }

                [data-testid="stSidebar"] .pg-sidebar-status {
                    background: #d1fae5;
                    border: 1px solid #6ee7b7;
                    border-radius: 9px;
                    padding: 10px 12px;
                    font-size: 0.88rem;
                    font-weight: 700;
                    margin: 10px 0;
                }

                [data-testid="stSidebar"] div.stButton > button {
                    background: #f8fafc !important;
                    color: #14243b !important;
                    border: 1px solid #cbd5e1 !important;
                    font-weight: 700;
                }

                [data-testid="stSidebar"] div.stButton > button:hover {
                    background: #e2e8f0 !important;
                    color: #0f172a !important;
                    border-color: #94a3b8 !important;
                }

                .block-container {
                    padding-top: 2rem;
                    padding-bottom: 3rem;
                    max-width: 1450px;
                }

                h1, h2, h3 {
                    color: #172b4d;
                }

                div[data-testid="stMetric"] {
                    background: #ffffff;
                    border: 1px solid #e5eaf2;
                    padding: 17px 18px;
                    border-radius: 13px;
                    box-shadow: 0 2px 8px rgba(20, 36, 59, 0.04);
                }

                div[data-testid="stForm"] {
                    background: #ffffff;
                    border: 1px solid #e5eaf2;
                    border-radius: 13px;
                    padding: 20px;
                }

                div.stButton > button,
                div.stFormSubmitButton > button {
                    border-radius: 9px;
                    font-weight: 600;
                    min-height: 42px;
                }

                div.stButton > button[kind="primary"],
                div.stFormSubmitButton > button[kind="primary"] {
                    background: #2563eb;
                    border-color: #2563eb;
                }

                div[data-testid="stExpander"] {
                    background: #ffffff;
                    border-radius: 10px;
                    border: 1px solid #e5eaf2;
                }

                .pg-subtitle {
                    color: #64748b;
                    margin-top: -10px;
                    margin-bottom: 20px;
                }

                .pg-section {
                    color: #172b4d;
                    font-size: 1.05rem;
                    font-weight: 700;
                    margin-top: 8px;
                    margin-bottom: 8px;
                }

                .pg-small {
                    color: #64748b;
                    font-size: 0.85rem;
                }

                .pg-risk {
                    padding: 5px 10px;
                    border-radius: 20px;
                    font-weight: 700;
                    font-size: 0.78rem;
                    display: inline-block;
                }
            </style>
            """,
            unsafe_allow_html=True,
        )

    def _render_sidebar(self):
        with st.sidebar:
            st.markdown(
                """
                <div style="padding: 10px 0 4px 0;">
                    <div style="font-size: 27px; font-weight: 800; color: white;">
                        🛡️ PhishGuard
                    </div>
                    <div style="font-size: 10px; letter-spacing: 1.4px;
                                color: #a9bad0; margin-top: 4px;">
                        AI-POWERED EMAIL SECURITY
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
                        st.progress(count / highest_threat_count)
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
                        st.progress(count / highest_status_count)
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
