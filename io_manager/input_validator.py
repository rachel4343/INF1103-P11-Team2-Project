## input_validator.py under io_manager.py
"""PhishGuard I/O: InputValidator definition."""
from __future__ import annotations

import re
from .io_config import MAX_URL_LENGTH

class InputValidator:
    EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    FILENAME = re.compile(r"^[\w\-. ()]+\.[A-Za-z0-9]{1,8}$")

    @classmethod
    def email(cls, text: str) -> bool:
        return bool(cls.EMAIL.fullmatch(text))

    @staticmethod
    def url(text: str) -> bool:
        # Same lightweight validation behaviour as the merged version.
        return " " not in text and "." in text and len(text) <= MAX_URL_LENGTH

    @classmethod
    def filename(cls, text: str) -> bool:
        return bool(cls.FILENAME.fullmatch(text))

