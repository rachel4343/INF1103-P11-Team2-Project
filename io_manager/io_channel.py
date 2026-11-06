## io_channel.py under io_manager.py
"""PhishGuard I/O: IOChannel definition."""
from __future__ import annotations

from abc import ABC, abstractmethod

class IOChannel(ABC):
    """Abstract interface: replace the terminal with scripted input for tests."""
    @abstractmethod
    def read(self, prompt: str = "") -> str: 
        ...

    @abstractmethod
    def read_secret(self, prompt: str = "") -> str: 
        ...

    @abstractmethod
    def write(self, text: str = "") -> None: 
        ...

