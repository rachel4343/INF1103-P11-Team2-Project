import json
import os
import time
from typing import Dict, List, Optional

from .record_store import RecordStore


class JsonRecordStore(RecordStore):
    """Keeps reports in one JSON file.

    An unreadable file is moved aside as a backup instead of being wiped, and a
    save goes to a temporary file first, so a crash cannot leave a half-written file.
    """

    DEFAULT_PATH = "phishguard_reports.json"
    PATH_VARIABLE = "PHISHGUARD_DATA_FILE"

    def __init__(self, path: Optional[str] = None):
        super().__init__()
        self.__path = path or os.environ.get(self.PATH_VARIABLE) or self.DEFAULT_PATH

    @property
    def path(self) -> str:
        return self.__path

    def load_all(self) -> List[Dict]:
        if not os.path.exists(self.__path):
            return []
        try:
            with open(self.__path, "r", encoding="utf-8") as file:
                data = json.load(file)
            if isinstance(data, list):
                return data
        except (ValueError, OSError):
            pass
        self._keep_unreadable_file()
        return []

    def save_all(self, records: List[Dict]) -> bool:
        temp_path = self.__path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as file:
                json.dump(records, file, indent=2)
            os.replace(temp_path, self.__path)
            return True
        except (OSError, TypeError, ValueError) as error:
            self._remove_quietly(temp_path)
            self._add_warning(f"Could not save reports to {self.__path}: {error}")
            return False

    def _keep_unreadable_file(self) -> None:
        backup = f"{self.__path}.corrupt-{time.strftime('%Y%m%d%H%M%S')}"
        try:
            os.replace(self.__path, backup)
            self._add_warning(f"Unreadable data file, kept as {backup}")
        except OSError as error:
            self._add_warning(f"Unreadable data file could not be set aside: {error}")

    @staticmethod
    def _remove_quietly(path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass