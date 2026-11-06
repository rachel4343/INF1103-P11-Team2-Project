## extraction_error.py under io_manager.py
"""PhishGuard I/O: ExtractionError definition."""
from __future__ import annotations


class ExtractionError(Exception):
    """Screenshot OCR or parsing failed."""

