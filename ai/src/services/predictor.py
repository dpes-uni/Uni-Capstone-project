"""
predictor.py

Loads the trained machine learning model and predicts
the risk level for a login attempt.
"""

from pathlib import Path

import joblib
import pandas as pd

from config import settings
from models.login_attempt import LoginAttempt
from models.recommended_action import RecommendedAction
from models.risk_level import RiskLevel
from models.risk_result import RiskResult
from services.feature_engineer import FeatureEngineer


class Predictor:
    """
    Uses the trained machine learning model to predict
    the risk level of a login attempt.
    """

    def __init__(self):

        # Resolve relative to the project root (ai/) so the model loads
        # regardless of the process working directory.
        project_root = (
            Path(__file__).resolve().parent.parent.parent
        )

        model_path = (
            project_root
            / "models"
            / "trained"
            / settings.MODEL_FILENAME
        )

        if not model_path.exists():
            raise FileNotFoundError(
                f"Model not found: {model_path}\n"
                "Train the model before making predictions."
            )

        self.pipeline = joblib.load(model_path)

    def predict(
        self,
        login: LoginAttempt
    ) -> RiskResult:
        """
        Predict the risk level for a login attempt.

        Args:
            login: LoginAttempt object.

        Returns:
            RiskResult
        """

        # --------------------------------------------------
        # Convert LoginAttempt into ML Features
        # --------------------------------------------------

        features = FeatureEngineer.to_features(
            login
        )

        dataframe = pd.DataFrame(
            [features]
        )

        # --------------------------------------------------
        # Predict Risk Level
        # --------------------------------------------------

        prediction = self.pipeline.predict(
            dataframe
        )[0]

        # --------------------------------------------------
        # Prediction Confidence
        # --------------------------------------------------

        if hasattr(
            self.pipeline,
            "predict_proba"
        ):

            probabilities = (
                self.pipeline.predict_proba(
                    dataframe
                )[0]
            )

            confidence = float(
                max(probabilities)
            )

        else:

            confidence = 1.0

        # --------------------------------------------------
        # Convert Prediction to RiskLevel
        # --------------------------------------------------

        prediction = prediction.lower()

        if prediction == "low":

            risk_level = RiskLevel.LOW

        elif prediction == "medium":

            risk_level = RiskLevel.MEDIUM

        else:

            risk_level = RiskLevel.HIGH

        # --------------------------------------------------
        # Determine Recommended Action
        # --------------------------------------------------

        if risk_level == RiskLevel.LOW:

            action = (
                RecommendedAction.ALLOW_LOGIN
            )

        elif risk_level == RiskLevel.MEDIUM:

            action = (
                RecommendedAction.REQUIRE_EMAIL_OTP
            )

        else:

            action = (
                RecommendedAction
                .REQUIRE_ADDITIONAL_VERIFICATION
            )

        # --------------------------------------------------
        # Convert Risk Level to Risk Score
        #
        # IMPORTANT:
        # Confidence is NOT the risk score.
        # --------------------------------------------------

        risk_scores = {
            RiskLevel.LOW: 20,
            RiskLevel.MEDIUM: 50,
            RiskLevel.HIGH: 80,
        }

        risk_score = risk_scores[
            risk_level
        ]

        # --------------------------------------------------
        # Return Risk Result
        # --------------------------------------------------

        return RiskResult(
            risk_score=risk_score,
            risk_level=risk_level,
            recommended_action=action,
            reason=(
                "Machine Learning prediction "
                f"({confidence:.1%} confidence)"
            ),
        )