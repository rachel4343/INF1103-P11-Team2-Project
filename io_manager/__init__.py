# ==============================================
#  PHISHGUARD — I/O Manager Package
#  INF1103 Phase 2
# ==============================================

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

# Menu System
from .menu_choice import MenuChoice

# MAIN Entry Point
from .io_manager import IOManager