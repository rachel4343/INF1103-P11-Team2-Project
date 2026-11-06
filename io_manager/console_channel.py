## console_channel.py under io_manager.py
"""PhishGuard I/O: ConsoleChannel definition."""
from __future__ import annotations

import getpass
from .io_channel import IOChannel

class ConsoleChannel(IOChannel):
    def read(self, prompt="") -> str:
        return input(prompt)

    def read_secret(self, prompt="") -> str:
        return getpass.getpass(prompt)

    def write(self, text="") -> None:
        print(text)

