"""
login_attempt.py

Domain model representing a single login attempt.

This model is shared across the AI module and is used by:

- Rule-based Risk Calculator
- Machine Learning Predictor
- Feature Engineering
- Logging
- Node.js Integration
"""

from dataclasses import dataclass, asdict
import json


@dataclass(slots=True)
class LoginAttempt:
    """
    Represents a single login attempt.
    """

    # ======================================================
    # User Information
    # ======================================================

    username: str

    # ======================================================
    # Device Information
    # ======================================================

    device: str
    browser: str
    operating_system: str

    # ======================================================
    # Network Information
    # ======================================================

    ip_address: str
    country: str
    city: str

    # ======================================================
    # Login Information
    # ======================================================

    login_hour: int
    failed_login_attempts: int

    # ======================================================
    # Security Information
    # ======================================================

    new_device: bool
    vpn_detected: bool
    trusted_device: bool
    trusted_location: bool

    # ======================================================
    # Factory Methods
    # ======================================================

    @classmethod
    def from_dict(cls, data: dict):
        """
        Create a LoginAttempt from a dictionary.
        """

        return cls(
            username=data["username"],
            device=data["device"],
            browser=data["browser"],
            operating_system=data["operating_system"],
            ip_address=data["ip_address"],
            country=data["country"],
            city=data["city"],
            login_hour=data["login_hour"],
            failed_login_attempts=data["failed_login_attempts"],
            new_device=data["new_device"],
            vpn_detected=data["vpn_detected"],
            trusted_device=data["trusted_device"],
            trusted_location=data["trusted_location"],
        )

    # ======================================================
    # Export Methods
    # ======================================================

    def to_dict(self) -> dict:
        """
        Convert object to dictionary.
        """

        return asdict(self)

    def to_json(self) -> str:
        """
        Convert object to JSON.
        """

        return json.dumps(
            self.to_dict(),
            indent=4,
        )

    # ======================================================
    # Validation
    # ======================================================

    def validate(self):
        """
        Validate the login attempt.

        Raises:
            ValueError if invalid.
        """

        if not (0 <= self.login_hour <= 23):
            raise ValueError(
                "Login hour must be between 0 and 23."
            )

        if self.failed_login_attempts < 0:
            raise ValueError(
                "Failed login attempts cannot be negative."
            )

    # ======================================================
    # Display
    # ======================================================

    def __str__(self) -> str:

        return (
            "\n"
            "========== Login Attempt ==========\n"
            f"Username             : {self.username}\n"
            f"Device               : {self.device}\n"
            f"Browser              : {self.browser}\n"
            f"Operating System     : {self.operating_system}\n"
            f"IP Address           : {self.ip_address}\n"
            f"Country              : {self.country}\n"
            f"City                 : {self.city}\n"
            f"Login Hour           : {self.login_hour}\n"
            f"Failed Attempts      : {self.failed_login_attempts}\n"
            f"New Device           : {self.new_device}\n"
            f"VPN Detected         : {self.vpn_detected}\n"
            f"Trusted Device       : {self.trusted_device}\n"
            f"Trusted Location     : {self.trusted_location}\n"
        )