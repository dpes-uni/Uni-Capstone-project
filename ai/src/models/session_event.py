"""
session_event.py

Represents user behaviour during an authenticated session.
"""

from dataclasses import dataclass


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

    def to_dict(self) -> dict:
        """
        Convert the session event into a dictionary.
        """

        return {
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
        )