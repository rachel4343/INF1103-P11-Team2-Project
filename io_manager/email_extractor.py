## email_extractor.py under io_manager.py
"""PhishGuard I/O: EmailExtractor definition."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict

class EmailExtractor(ABC):
    """Common interface for local screenshot text extractors."""
    label = "local OCR"

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def extract(self, image_path: str) -> Dict: ...

