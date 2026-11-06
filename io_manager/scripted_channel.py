## scripted_channel.py under io_manager.py
"""PhishGuard I/O: ScriptedChannel definition."""
from __future__ import annotations

from collections import deque
from typing import List, Sequence
from .io_channel import IOChannel

class ScriptedChannel(IOChannel):
    """Test double: supply responses and examine printed output."""
    def __init__(self, answers: Sequence[str] = ()):
        self._answers = deque(answers)
        self.output: List[str] = []

    def read(self, prompt="") -> str:
        self.output.append(prompt)
        if not self._answers:
            raise EOFError("scripted input exhausted")
        return self._answers.popleft()

    def read_secret(self, prompt="") -> str:
        return self.read(prompt)

    def write(self, text="") -> None:
        self.output.append(str(text))

    @property
    def transcript(self) -> str:
        return "\n".join(self.output)

