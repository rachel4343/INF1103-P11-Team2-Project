## tesseract_extractor.py under io_manager.py
"""OCR extraction using the local Tesseract executable only."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable, Dict, Optional
from .email_extractor import EmailExtractor
from .extraction_error import ExtractionError
from .email_text_parser import EmailTextParser

class TesseractExtractor(EmailExtractor):
    """Implements the abstract extractor interface using local Tesseract OCR."""
    local_only = True
    label = "local Tesseract OCR"
    OCR_TIMEOUT_SECONDS = 30

    def __init__(self, parser: Optional[EmailTextParser] = None,
                 ocr_fn: Optional[Callable[[str], str]] = None,
                 timeout: int = OCR_TIMEOUT_SECONDS):
        self._parser = parser or EmailTextParser()
        self._timeout = timeout
        self._ocr_fn = ocr_fn  # injected fake for deterministic tests
        bundled_executable = (
            Path(__file__).resolve().parent
            / "vendor"
            / "tesseract"
            / "windows"
            / "tesseract.exe"
        )
        use_bundled = sys.platform == "win32" and bundled_executable.is_file()
        self._tesseract_executable = (
            str(bundled_executable) if use_bundled
            else shutil.which("tesseract")
        )
    def is_available(self) -> bool:
        if self._ocr_fn is not None:
            return True
        try:
            import pytesseract
            from PIL import Image
        except ImportError:
            return False
        return self._tesseract_executable is not None

    def extract(self, image_path: str) -> Dict:
        if not self.is_available():
            raise ExtractionError("Tesseract OCR is not installed")
        try:
            text = (self._ocr_fn or self._run_ocr)(image_path)
            fields = self._parser.parse(text)
            self._parser.validate_email_screenshot(text, fields)
            return fields
        except ExtractionError:
            raise
        except RuntimeError as exc:  # pytesseract raises RuntimeError on timeout
            if "timeout" in str(exc).lower():
                raise ExtractionError(f"OCR took longer than {self._timeout}s and was stopped") from exc
            raise ExtractionError(f"Local OCR failed: {exc}") from exc
        except Exception as exc:
            raise ExtractionError(f"Local OCR failed: {exc}") from exc

    def _run_ocr(self, path: str) -> str:
        import pytesseract
        from PIL import Image, ImageOps, ImageEnhance
        if self._tesseract_executable:
            pytesseract.pytesseract.tesseract_cmd = self._tesseract_executable
        with Image.open(path) as original:
            image = ImageOps.grayscale(original)
            if 0 < image.width < 1400:
                factor = 1400 / image.width
                image = image.resize((int(image.width * factor), int(image.height * factor)))
            image = ImageEnhance.Contrast(image).enhance(1.8)
            return pytesseract.image_to_string(image, config="--psm 6", timeout=self._timeout)
