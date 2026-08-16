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


class SessionPredictor:
    """
    Provides predictions using the trained
    Session Monitoring Machine Learning model.
    """

    def __init__(self, model_path=None):
        """
        Load the trained session model.
        """

        if model_path is None:

            project_root = Path(__file__).resolve().parent.parent.parent

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

    def predict(self, session: SessionEvent) -> dict:
        """
        Predict whether the session contains unusual activity.

        Returns a dictionary containing:

        - prediction
        - risk_level
        - confidence
        """

        data = session.to_dict()

        dataframe = pd.DataFrame([data])

        # Username is an identifier and is not used
        # as a behavioural ML feature.
        if "username" in dataframe.columns:
            dataframe = dataframe.drop(
                columns=["username"]
            )

        # The target field must never be provided
        # to the model during prediction.
        if "unusual_activity" in dataframe.columns:
            dataframe = dataframe.drop(
                columns=["unusual_activity"]
            )

        # Convert boolean feature to integer.
        dataframe["rapid_actions"] = (
            dataframe["rapid_actions"].astype(int)
        )

        prediction = self.model.predict(dataframe)[0]

        probabilities = self.model.predict_proba(
            dataframe
        )[0]

        confidence = float(max(probabilities))

        # Convert NumPy boolean to normal Python bool.
        is_unusual = bool(prediction)

        if is_unusual:
            risk_level = "High"
        else:
            risk_level = "Low"

        return {
            "unusual_activity": is_unusual,
            "risk_level": risk_level,
            "confidence": round(confidence, 4),
        }