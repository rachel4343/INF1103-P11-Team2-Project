from typing import Dict, List, Optional

from .personnel_report import PersonnelReport
from .personnel_searcher import PersonnelSearcher
from .record_store import RecordStore

class ITPersonnel:
    """ Manage IT staff records, assignments and review statistics."""

    def __init__(self, personnel: Optional[List[Dict]] = None, store: Optional[RecordStore] = None):
        self.__store = store
        if personnel is not None:
            start = personnel
        elif store is not None:
            start = store.load_all()
        else:
            start = []
        self.__personnel = [dict(person) for person in start if isinstance(person, dict)]
        self.__searcher = PersonnelSearcher()
        self.__report = PersonnelReport()
    @property
    def personnel(self) -> List[Dict]:
        return list(self.__personnel)

    def add_person(self, person: Dict) -> bool:
        staff_id = str(person.get("staff_id", "")).strip()
        if not staff_id or not person.get("name") or self.find_person(staff_id):
            return False
        person = dict(person)
        person["staff_id"] = staff_id
        person.setdefault("active", True)
        self.__personnel.append(person)
        if not self.save_personnel():
            self.__personnel.pop()
            return False
        return True

    def set_active(self, staff_id: str, active: bool) -> bool:
        person = self.find_person(staff_id)
        if person is None:
            return False
        previous = person.get("active", True)
        person["active"] = bool(active)
        if not self.save_personnel():
            person["active"] = previous
            return False
        return True

    def find_person(self, staff_id: str) -> Optional[Dict]:
        wanted = str(staff_id).strip().upper()
        for person in self.__personnel:
            if str(person.get("staff_id", "")).upper() == wanted:
                return person
            return None

    def save_personnel(self) -> bool:
        return self.__store.save_all(self.__personnel) if self.__store else True

    def take_warnings(self) -> List[str]:
        return self.__store.take_warnings() if self.store else []

    def search_personnel(self, text: str) -> List[Dict]:
        return self.__searcher.search_personnel(self.__personnel, text)

    def filter_personnel(self, **criteria) -> List[Dict]:
        return self.__searcher.filter_personnel(self.__personnel, **criteria)

    def build_report(self, records: List[Dict]) -> Dict:
        return self.__report.build_report(self.__personnel, records)

    def save_report(self, records: List[Dict], path: str) -> bool:
        return self.__report.save_report(self.__personnel, records, path)