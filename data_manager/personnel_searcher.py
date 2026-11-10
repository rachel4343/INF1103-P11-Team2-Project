from typing import Dict, List

class PersonnelSearcher:
    search_fields = ("staff_id", "name", "email", "role", "department")
    exact_filters = ("role", "department")
    other_filters = ("active")

    def search_personnel(self, personnel: List[Dict], text: str) -> List[Dict]:
        words = str(text or "").lower().split()
        found = []
        for person in personnel:
            if not isinstance(person, dict):
                continue
            haystack = " ".join(str(person.get(field, "")) for field in self.search_fields).lower()
            if all(word in haystack for word in words):
                found.append(person)
        return found

    def filter_personnel(self, personnel: List[Dict], **criteria) -> List[Dict]:
        unknown = set(criteria) - set(self.exact_filters) - set(self.other_filters)
        if unknown:
            raise ValueError(f"Unknown Filter: {', '.join(sorted(unknown))}")
        active = {key: value for key, value in criteria.items() if value is not None}
        return [person for person in personnel
                if isinstance(person, dict)
                and all(self._matches(person, key, value) for key, value in active.items())]

    @staticmethod
    def _matches(person: Dict, key: str, value) -> bool:
        if key == "active":
            return bool(person.get("active", True)) == bool(value)
        return str(person.get(key, "")).strip().lower() == str(value).strip().lower()