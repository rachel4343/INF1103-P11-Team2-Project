from abc import ABC, abstractmethod
from typing import Dict, List


class RecordStore(ABC):
    """The contract for anywhere reports can be kept (a JSON file, memory, later a database).

    load_all never raises: a missing or damaged store gives an empty list.
    save_all returns True when the records were saved and False when they were not.
    Problems are reported as warnings, never printed here.
    """

    def __init__(self):
        self.__warnings = []

    @abstractmethod
    def load_all(self) -> List[Dict]:
        """Return every saved record (an empty list if there are none)."""

    @abstractmethod
    def save_all(self, records: List[Dict]) -> bool:
        """Replace the saved records with this list. True if it worked."""

    def take_warnings(self) -> List[str]:
        """Hand over the warnings collected so far, and forget them."""
        warnings, self.__warnings = self.__warnings, []
        return warnings

    def _add_warning(self, message: str) -> None:
        self.__warnings.append(message)