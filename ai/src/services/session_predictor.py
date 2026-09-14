"""
session_predictor.py

Loads the trained Session Monitoring AI model
and predicts whether an authenticated session
contains unusual activity.
"""

from pathlib import Path

import joblib
import pandas as pd

from models.session_event import SessionEvent
from models.risk_level import RiskLevel
from models.recommended_action import RecommendedAction
from models.risk_result import RiskResult


class SessionPredictor:
    """
    Provides predictions using the trained
    Session Monitoring Machine Learning model.
    """

    def __init__(self, model_path=None):

        if model_path is None:

            project_root = (
                Path(__file__).resolve().parent.parent.parent
            )

            model_path = (
                project_root
                / "models"
                / "trained"
                / "session_risk_model.pkl"
            )

        self.model_path = Path(model_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Session model not found: {self.model_path}"
            )

        self.model = joblib.load(self.model_path)

    # ------------------------------------------------------
    # Prediction
    # ------------------------------------------------------

    def predict(self, session: SessionEvent) -> RiskResult:
        """
        Predict the risk level of an authenticated session.

        Returns:
            RiskResult
        """

        data = session.to_dict()

        dataframe = pd.DataFrame([data])

        # Username is an identifier and is not
        # used as a behavioural ML feature.
        if "username" in dataframe.columns:
            dataframe = dataframe.drop(
                columns=["username"]
            )

        # Target must never be supplied to the model.
        if "unusual_activity" in dataframe.columns:
            dataframe = dataframe.drop(
                columns=["unusual_activity"]
            )

        # Convert boolean feature to integer.
        dataframe["rapid_actions"] = (
            dataframe["rapid_actions"].astype(int)
        )

        # --------------------------------------------------
        # Model Prediction
        # --------------------------------------------------

        prediction = self.model.predict(
            dataframe
        )[0]

        # --------------------------------------------------
        # Prediction Confidence
        # --------------------------------------------------

        if hasattr(self.model, "predict_proba"):

            probabilities = self.model.predict_proba(
                dataframe
            )[0]

            confidence = float(
                max(probabilities)
            )

        else:

            confidence = 1.0

        # --------------------------------------------------
        # Convert Prediction to Risk Level
        # --------------------------------------------------

        is_unusual = bool(prediction)

        if is_unusual:

            risk_level = RiskLevel.HIGH

            action = (
                RecommendedAction
                .REQUIRE_ADDITIONAL_VERIFICATION
            )

        else:

            risk_level = RiskLevel.LOW

            action = (
                RecommendedAction.ALLOW_LOGIN
            )

        # --------------------------------------------------
        # Risk Score
        #
        # Risk score represents risk.
        # Confidence remains separate.
        # --------------------------------------------------

        risk_scores = {
            RiskLevel.LOW: 20,
            RiskLevel.MEDIUM: 50,
            RiskLevel.HIGH: 80,
        }

        risk_score = risk_scores[risk_level]

        # --------------------------------------------------
        # Result
        # --------------------------------------------------

        return RiskResult(
            risk_score=risk_score,
            risk_level=risk_level,
            recommended_action=action,
            reason=self._build_reason(is_unusual, confidence, session),
        )

    def _build_reason(self, is_unusual: bool, confidence: float, session: SessionEvent) -> str:
        """Build a human-readable reason including context-change signals."""
        parts = [
            f"unusual_activity={is_unusual}",
            f"confidence={confidence:.1%}",
        ]

        ctx = session.context_changes or {}
        changes = []
        if ctx.get("deviceChanged"):
            changes.append("device")
        if ctx.get("browserChanged"):
            changes.append("browser")
        if ctx.get("osChanged"):
            changes.append("OS")
        if ctx.get("locationChanged"):
            changes.append("location")
        if ctx.get("vpnChanged"):
            changes.append("VPN")
        if ctx.get("ipChanged"):
            changes.append("IP/country")

        if changes:
            parts.append(f"context_changes=[{', '.join(changes)}]")

        return "Session ML prediction: " + ", ".join(parts)