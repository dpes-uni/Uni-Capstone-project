"""
session_event.py

Represents user behaviour during an authenticated session.
Includes optional context-change signals for security monitoring.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionEvent:
    """
    Represents a single session behaviour record.
    """

    username: str
    user_role: str

    session_duration_minutes: int

    documents_viewed: int
    documents_downloaded: int
    documents_uploaded: int
    verification_actions: int

    failed_actions: int
    rapid_actions: bool
    unusual_activity: bool

    # Optional context-change signals from Node.js session monitor.
    context_changes: Optional[dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Convert the session event into a dictionary.
        """

        d = {
            "username": self.username,
            "user_role": self.user_role,
            "session_duration_minutes":
                self.session_duration_minutes,
            "documents_viewed":
                self.documents_viewed,
            "documents_downloaded":
                self.documents_downloaded,
            "documents_uploaded":
                self.documents_uploaded,
            "verification_actions":
                self.verification_actions,
            "failed_actions":
                self.failed_actions,
            "rapid_actions":
                self.rapid_actions,
            "unusual_activity":
                self.unusual_activity,
        }

        if self.context_changes:
            d["context_changes"] = self.context_changes

        return d

    @classmethod
    def from_dict(cls, data: dict):
        """
        Create a SessionEvent from a dictionary.
        """

        return cls(
            username=data["username"],
            user_role=data["user_role"],
            session_duration_minutes=int(
                data["session_duration_minutes"]
            ),
            documents_viewed=int(
                data["documents_viewed"]
            ),
            documents_downloaded=int(
                data["documents_downloaded"]
            ),
            documents_uploaded=int(
                data["documents_uploaded"]
            ),
            verification_actions=int(
                data["verification_actions"]
            ),
            failed_actions=int(
                data["failed_actions"]
            ),
            rapid_actions=bool(
                data["rapid_actions"]
            ),
            unusual_activity=bool(
                data["unusual_activity"]
            ),
            context_changes=data.get("context_changes"),
        )