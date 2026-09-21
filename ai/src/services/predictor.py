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

    # --------------------------------------------------
    # Weighted score per class.
    #
    # Used to turn the model's full probability
    # distribution into a single 0-100 risk score,
    # instead of a fixed constant per predicted class.
    # --------------------------------------------------

    CLASS_SCORE_WEIGHTS = {
        "low": 15,
        "medium": 50,
        "high": 90,
    }

    # --------------------------------------------------
    # Below this confidence, the prediction is treated
    # as advisory only — the reason string flags it so
    # downstream consumers (DecisionEngine, logs, admin
    # dashboards) know the model wasn't sure.
    # --------------------------------------------------

    LOW_CONFIDENCE_THRESHOLD = 0.45

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

        prediction = prediction.lower()

        # --------------------------------------------------
        # Prediction Confidence + Weighted Risk Score
        #
        # IMPORTANT:
        # Confidence is NOT the risk score.
        #
        # The risk score is now derived from the full
        # probability distribution across all classes
        # (not just the winning class), so two "Medium"
        # predictions with different underlying confidence
        # no longer produce an identical score.
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

            classes = [
                str(class_label).lower()
                for class_label in self.pipeline.classes_
            ]

            proba_by_class = dict(
                zip(classes, probabilities)
            )

            confidence = float(
                max(probabilities)
            )

            risk_score = round(
                sum(
                    self.CLASS_SCORE_WEIGHTS.get(class_label, 50) * proba
                    for class_label, proba in proba_by_class.items()
                )
            )

        else:

            confidence = 1.0

            fallback_scores = {
                "low": 20,
                "medium": 50,
                "high": 80,
            }

            risk_score = fallback_scores.get(
                prediction, 50
            )

        # --------------------------------------------------
        # Convert Prediction to RiskLevel
        # --------------------------------------------------

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
        # Build Reason
        #
        # Flags low-confidence predictions so downstream
        # consumers know the result is advisory rather
        # than a strong signal.
        # --------------------------------------------------

        if confidence < self.LOW_CONFIDENCE_THRESHOLD:

            reason_suffix = (
                " (low confidence — treat as advisory)"
            )

        else:

            reason_suffix = ""

        reason = (
            "Machine Learning prediction "
            f"({confidence:.1%} confidence)"
            f"{reason_suffix}"
        )

        # --------------------------------------------------
        # Return Risk Result
        # --------------------------------------------------

        return RiskResult(
            risk_score=risk_score,
            risk_level=risk_level,
            recommended_action=action,
            reason=reason,
        )