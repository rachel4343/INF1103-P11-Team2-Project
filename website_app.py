# ==============================================
#  PHISHGUARD — Streamlit Web Interface
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
        "1. Submit Email Report",
        "2. IT Security Personnel",
        "3. Keyword Checker Tool",
        "4. Find a Report",
        "5. Exit",
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

    def render(self):
        st.set_page_config(page_title="PhishGuard", page_icon="🛡️")
        st.title("🛡️ PhishGuard")
        st.caption("AI-powered phishing detection and report management")

        entered_api_key = st.sidebar.text_input(
            "Gemini API key",
            type="password",
            key="gemini_api_key_input",
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

        choice = st.radio(
            "Main menu — choose an option",
            self.MENU_OPTIONS,
            key="main_menu_choice",
        )

        if choice == self.MENU_OPTIONS[0]:
            self._render_report_submission()
        elif choice == self.MENU_OPTIONS[1]:
            self._render_it_review()
        elif choice == self.MENU_OPTIONS[2]:
            self._render_keyword_checker()
        elif choice == self.MENU_OPTIONS[3]:
            self._render_report_search()
        else:
            st.info(
                "Thanks for using PhishGuard. You can close this browser tab. "
                "To stop the local server, press Ctrl+C in the terminal running Streamlit."
            )

    def _render_report_submission(self):
        st.header("Submit Email Report")
        input_method = st.radio(
            "How would you like to provide the email?",
            ("Enter manually", "Upload an image for OCR"),
            horizontal=True,
            key="report_input_method",
        )

        extracted = {}
        if input_method == "Upload an image for OCR":
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
                if st.button("Extract email text from image"):
                    try:
                        extracted = self._extract_uploaded_image(image.name, image_bytes)
                        st.session_state["ocr_report_fields"] = extracted
                        st.rerun()
                    except (ValueError, ExtractionError) as error:
                        st.error(f"Could not read the screenshot: {error}")
                return

            extracted = st.session_state["ocr_report_fields"]
            st.success("Text extracted. Check and edit the fields below.")

        with st.form("report_submission"):
            sender_email = st.text_input(
                "Sender email", value=extracted.get("sender_email", "")
            )
            sender_name = st.text_input(
                "Sender display name", value=extracted.get("sender_name", "")
            )
            subject = st.text_input("Email subject", value=extracted.get("subject", ""))
            body = st.text_area(
                "Email message",
                value=extracted.get("body", ""),
                height=200,
            )
            urls = st.text_input(
                "URLs found (comma-separated)",
                value=", ".join(extracted.get("urls", [])),
            )
            clicked_link = st.checkbox("I clicked a link")
            opened_attachment = st.checkbox("I opened an attachment")
            entered_information = st.checkbox("I entered personal or account information")
            submitted = st.form_submit_button("Analyze and submit")

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

        st.success(f"Report submitted. Your report ID is {report_id}.")
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

    def _render_keyword_checker(self):
        st.header("Keyword Checker")
        with st.form("keyword_scan"):
            text = st.text_area("Paste suspicious email text", height=200)
            deep_scan = st.checkbox("Also run the full AI analysis")
            submitted = st.form_submit_button("Scan")

        if not submitted:
            return
        if not text.strip():
            st.error("Enter some text to scan.")
            return

        result = self.keyword_checker.scan(text)
        st.subheader("Offline keyword scan")
        st.write(f"**Level:** {result['level'].title()}")
        st.write(f"**Score:** {result['score']}")
        for category, matches in result["found"].items():
            if matches:
                st.write(f"**{category.replace('_', ' ').title()}:** {', '.join(matches)}")

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

    def _it_authentication_gate(self):
        if st.session_state.get("it_authenticated", False):
            if st.button("Log out of IT Security"):
                st.session_state["it_authenticated"] = False
                st.rerun()
            return True

        st.warning("IT Security access requires authentication.")
        with st.form("it_authentication"):
            password = st.text_input("IT password", type="password")
            submitted = st.form_submit_button("Log in")
        if submitted:
            if self.logic_manager.verify_it_password(password):
                st.session_state["it_authenticated"] = True
                st.rerun()
            else:
                st.error("Incorrect password.")
        return False

    def _render_it_review(self):
        st.header("IT Security — Review and Manage")
        if not self._it_authentication_gate():
            return

        records = self.logic_manager.sort_records_by_priority(
            self.data_manager.load_records()
        )
        if not records:
            st.info("No reports have been submitted.")
            return

        report_id = st.selectbox(
            "Select a report",
            [record["report_id"] for record in records],
            key="review_report_id",
        )
        record_index = self.logic_manager.find_record_index(records, report_id)
        record = records[record_index]
        self._show_record(record)

        if record.get("review_stage") == "closed":
            st.info("This report is finalized and locked.")
            return

        self._render_review_form(records, record_index, record)

    def _render_review_form(self, records, record_index, record):
        st.subheader("Review this report")
        is_second_review = record.get("review_stage") == "awaiting_second_review"
        with st.form(f"review_{record['report_id']}"):
            reviewer = st.text_input(
                "Reviewer name",
                value=record.get("assigned_reviewer", "") if is_second_review else "",
            )
            if is_second_review:
                decision = st.radio("Decision", ("Approve", "Reject"))
                rejection_reason = (
                    st.text_area("Reason for rejection")
                    if decision == "Reject"
                    else ""
                )
                submitted = st.form_submit_button("Save second review")
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
                submitted = st.form_submit_button("Save first review")
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
        st.success("Review saved.")
        st.rerun()

    def _render_report_search(self):
        st.header("Find a Report")
        if not self._it_authentication_gate():
            return

        records = self.data_manager.load_records()
        if not records:
            st.info("No reports have been submitted.")
            return

        query = st.text_input("Search by report ID, sender, subject, or text")
        found = (
            self.data_manager.search_records(records, query)
            if query.strip()
            else records
        )
        if not found:
            st.info("No matching reports found.")
            return

        report_id = st.selectbox(
            "Matching reports",
            [record["report_id"] for record in found],
            key="search_report_id",
        )
        selected = self.data_manager.find_record(records, report_id)
        if selected:
            self._show_record(selected)

    @staticmethod
    def _show_ai_result(result):
        st.subheader("AI assessment")
        st.write(f"**Analysis mode:** {result.get('analysis_mode', 'unknown')}")
        st.write(f"**Threat:** {result.get('threat_level', 'unknown').title()}")
        st.write(f"**Confidence:** {result.get('confidence', 0):.0%}")
        st.write(f"**Attack type:** {result.get('attack_type', 'unknown')}")
        st.write(f"**Explanation:** {result.get('explanation', '')}")
        st.write(f"**Recommended action:** {result.get('recommended_action', '')}")

    def _show_record(self, record):
        st.write(f"**Report ID:** {record.get('report_id', 'unknown')}")
        st.write(f"**Priority:** {record.get('priority', 'unknown')}")
        st.write(f"**Review status:** {record.get('review_status', 'unknown')}")
        st.write(f"**Risk score:** {record.get('risk_score', 0)}/100")
        if record.get("ai_analysis"):
            self._show_ai_result(record["ai_analysis"])
        elif record.get("ai_error"):
            st.warning(f"AI result unavailable: {record['ai_error']}")
        st.json(record.get("report") or {})

    def _show_store_warnings(self):
        for warning in self.data_manager.take_warnings():
            st.warning(warning)


if __name__ == "__main__":
    PhishGuardWebApp().render()