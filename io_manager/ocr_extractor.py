## ocr_extractor.py under io_manager.py
"""Backward-compatible imports for the split OCR classes.

New code can import directly from io_components/email_text_parser.py and
io_components/tesseract_extractor.py. No classes are defined in this file.
"""
from io_components.email_text_parser import EmailTextParser
from io_components.tesseract_extractor import TesseractExtractor

__all__ = ["EmailTextParser", "TesseractExtractor"]
