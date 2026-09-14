"""
recommended_action.py

Defines the actions the system can recommend
after evaluating a login attempt.
"""

from enum import Enum


class RecommendedAction(Enum):
    """
    Recommended security action.
    """

    ALLOW_LOGIN = "Allow Login"
    REQUIRE_EMAIL_OTP = "Require Email OTP"
    REQUIRE_ADDITIONAL_VERIFICATION = (
        "Require Additional Verification"
    )
    BLOCK_LOGIN = "Block Login"

    def __str__(self) -> str:
        return self.value