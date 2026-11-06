# email_report.py under ai_manager.py

from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class EmailReport:
    """Normalized representation of a raw email report."""

    subject: str = ""
    body: str = ""
    sender_name: str = ""
    sender_email: str = ""
    links: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)

    @staticmethod
    def _as_list(value) -> list:
        value = value or []
        return [value] if isinstance(value, str) else list(value)
    @classmethod
    def from_dict(cls, report: Dict) -> "EmailReport":
        return cls(
            subject=str(report.get("subject") or ""),
            body=str(report.get("body") or ""),
            sender_name=str(report.get("sender_name") or report.get("sender") or ""),
            sender_email=str(report.get("sender_email") or ""),
            links=cls._as_list(report.get("links") or report.get("urls")),
            attachments=cls._as_list(report.get("attachments")),
        )

    @property
    def full_text(self) -> str:
        return f"{self.subject} {self.body}".lower()

    @property
    def sender_info(self) -> str:
        return f"{self.sender_name} {self.sender_email}".lower()
   