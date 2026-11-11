# ==============================================
#  PHISHGUARD — I/O Manager Package
#  INF1103 Phase 2
# ==============================================

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

# Preserve the CLI's earlier function-based interface while the package API
# exposes IOManager and its supporting classes.
_legacy_path = Path(__file__).resolve().parent.parent / "io_manager.py"
_legacy_spec = spec_from_file_location("_io_manager_compat", _legacy_path)
if _legacy_spec is None or _legacy_spec.loader is None:
    raise ImportError(f"Could not load legacy I/O helpers from {_legacy_path}")
_legacy_io = module_from_spec(_legacy_spec)
_legacy_spec.loader.exec_module(_legacy_io)

for _name in (
    "display_header",
    "display_message",
    "display_error",
    "display_assessment",
    "display_record_list",
    "display_record_detail",
    "display_keyword_results",
    "prompt_menu_number",
    "prompt_choice",
    "prompt_text",
    "collect_report_input",
    "collect_review_update",
    "collect_record_id",
    "collect_keyword_text",
    "prompt_it_password",
):
    globals()[_name] = getattr(_legacy_io, _name)

# Core Configuration
from .io_config import (
    MAX_FIELD_LENGTH, MAX_BODY_LENGTH, MAX_URL_LENGTH,
    BODY_END_MARKER, LINE_WIDTH, MAX_NOTE, MAX_NAME,
    MAX_IMAGE, MAX_FILE, INDICATORS
)
from .io_helpers import clean, short

# Channel System
from .io_channel import IOChannel
from .console_channel import ConsoleChannel
from .scripted_channel import ScriptedChannel

# Input Validation
from .input_validator import InputValidator

# Privacy Protection
from .privacy_filter import PrivacyFilter

# File & Attachment Handling
from .attachment_reader import AttachmentReader
from .image_evidence_store import ImageEvidenceStore

# OCR & Email Extraction
from .extraction_error import ExtractionError
from .email_extractor import EmailExtractor
from .email_text_parser import EmailTextParser
from .tesseract_extractor import TesseractExtractor
from .ocr_extractor import EmailTextParser, TesseractExtractor  # backward compat

# Keyword Checking
from .keyword_checker import KeywordChecker
from .io_manager import display_ai_keyword_result

# Keep the plural name imported by the original CLI entry point.
display_ai_keyword_results = display_ai_keyword_result

# Menu System
from .menu_choice import MenuChoice

# MAIN Entry Point
from .io_manager import IOManager