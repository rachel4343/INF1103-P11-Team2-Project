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
