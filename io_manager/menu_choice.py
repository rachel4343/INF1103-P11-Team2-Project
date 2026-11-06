## menu_choice.py under io_manager.py
"""PhishGuard I/O: MenuChoice definition."""
from __future__ import annotations

from enum import Enum

class MenuChoice(Enum):
    SUBMIT_REPORT = 1
    IT_PANEL = 2
    KEYWORD_CHECKER = 3
    EXIT = 4

