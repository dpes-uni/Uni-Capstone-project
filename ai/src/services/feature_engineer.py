"""
feature_engineer.py

Converts LoginAttempt objects into numerical features
used by the machine learning model.
"""

from models.login_attempt import LoginAttempt


class FeatureEngineer:
    """
    Converts LoginAttempt objects into machine learning features.
    """

    @staticmethod
    def to_features(login: LoginAttempt) -> dict:
        """
        Convert a LoginAttempt into a dictionary of ML features.
        """

        return {
            "login_hour": login.login_hour,
            "failed_login_attempts": login.failed_login_attempts,

            "new_device": int(login.new_device),
            "vpn_detected": int(login.vpn_detected),
            "trusted_device": int(login.trusted_device),
            "trusted_location": int(login.trusted_location),

            "country": login.country,
            "city": login.city,
            "device": login.device,
            "browser": login.browser,
            "operating_system": login.operating_system,
        }

    @staticmethod
    def feature_names() -> list[str]:
        """
        Returns the feature names used by the ML model.
        """

        return [
            "login_hour",
            "failed_login_attempts",
            "new_device",
            "vpn_detected",
            "trusted_device",
            "trusted_location",
            "country",
            "city",
            "device",
            "browser",
            "operating_system",
        ]