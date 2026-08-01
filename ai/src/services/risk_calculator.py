"""
risk_calculator.py

Calculates the rule-based risk score for a login attempt.
"""

from config import settings

from models.login_attempt import LoginAttempt
from models.risk_result import RiskResult
from models.risk_level import RiskLevel
from models.recommended_action import RecommendedAction


class RiskCalculator:
    """
    Calculates the risk score of a login attempt.
    """

    def calculate(self, login: LoginAttempt) -> RiskResult:

        score = 0
        reasons = []

        # --------------------------------------------------
        # New Device
        # --------------------------------------------------

        if login.new_device:
            score += settings.NEW_DEVICE_POINTS
            reasons.append("New device detected")

        # --------------------------------------------------
        # VPN
        # --------------------------------------------------

        if login.vpn_detected:
            score += settings.VPN_POINTS
            reasons.append("VPN detected")

        # --------------------------------------------------
        # Failed Login Attempts
        # --------------------------------------------------

        if (
            login.failed_login_attempts
            >= settings.MAX_FAILED_LOGIN_ATTEMPTS
        ):
            score += settings.FAILED_LOGIN_POINTS
            reasons.append("Multiple failed login attempts")

        # --------------------------------------------------
        # Outside Business Hours
        # --------------------------------------------------

        if (
            login.login_hour < settings.BUSINESS_START_HOUR
            or login.login_hour > settings.BUSINESS_END_HOUR
        ):
            score += settings.OUTSIDE_BUSINESS_HOURS_POINTS
            reasons.append("Login outside business hours")

        # --------------------------------------------------
        # New Location
        # --------------------------------------------------

        if not login.trusted_location:
            score += settings.NEW_LOCATION_POINTS
            reasons.append("Untrusted location")

        # --------------------------------------------------
        # Determine Risk Level
        # --------------------------------------------------

        if score <= settings.LOW_RISK_MAX:

            risk_level = RiskLevel.LOW
            action = RecommendedAction.ALLOW_LOGIN

        elif score <= settings.MEDIUM_RISK_MAX:

            risk_level = RiskLevel.MEDIUM
            action = RecommendedAction.REQUIRE_EMAIL_OTP

        else:

            risk_level = RiskLevel.HIGH
            action = (
                RecommendedAction.REQUIRE_ADDITIONAL_VERIFICATION
            )

        # --------------------------------------------------
        # Build Reason
        # --------------------------------------------------

        if not reasons:
            reasons.append("No unusual behaviour detected")

        reason = ", ".join(reasons)

        return RiskResult(
            risk_score=score,
            risk_level=risk_level,
            recommended_action=action,
            reason=reason,
        )
    