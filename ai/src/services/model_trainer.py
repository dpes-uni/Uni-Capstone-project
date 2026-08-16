"""
model_trainer.py

Trains the machine learning model used by the
AI-Assisted Anomaly Detection System.
"""

from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from config import settings
from utils.csv_loader import CSVLoader


class ModelTrainer:
    """
    Trains and saves the machine learning model.
    """

    def train(self):

        # ------------------------------------------
        # Load Dataset
        # ------------------------------------------

        dataframe = CSVLoader.load(settings.RAW_DATASET)

        # ------------------------------------------
        # Features and Labels
        # ------------------------------------------

        X = dataframe.drop(columns=["risk_level"])

        y = dataframe["risk_level"]

        # ------------------------------------------
        # Categorical Columns
        # ------------------------------------------

        categorical_features = [
            "country",
            "city",
            "device",
            "browser",
            "operating_system"
        ]

        # ------------------------------------------
        # Numerical Columns
        # ------------------------------------------

        numerical_features = [
            "login_hour",
            "failed_login_attempts",
            "new_device",
            "vpn_detected",
            "trusted_device",
            "trusted_location"
        ]

        # ------------------------------------------
        # Pre-processing
        # ------------------------------------------

        preprocessor = ColumnTransformer(

            transformers=[

                (
                    "categorical",
                    OneHotEncoder(handle_unknown="ignore"),
                    categorical_features,
                ),

                (
                    "numerical",
                    "passthrough",
                    numerical_features,
                ),
            ]
        )

        # ------------------------------------------
        # Machine Learning Model
        # ------------------------------------------

        model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
        )

        pipeline = Pipeline(

            steps=[

                ("preprocessor", preprocessor),

                ("classifier", model),

            ]
        )

        # ------------------------------------------
        # Train/Test Split
        # ------------------------------------------

        X_train, X_test, y_train, y_test = train_test_split(

            X,

            y,

            test_size=0.2,

            random_state=42,

            stratify=y,
        )

        # ------------------------------------------
        # Train
        # ------------------------------------------

        pipeline.fit(X_train, y_train)

        # ------------------------------------------
        # Evaluate
        # ------------------------------------------

        predictions = pipeline.predict(X_test)

        accuracy = accuracy_score(
            y_test,
            predictions,
        )

        print(f"Model Accuracy: {accuracy:.2%}")

        # ------------------------------------------
        # Save Model
        # ------------------------------------------

        model_path = Path("models/trained")

        model_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        joblib.dump(
            pipeline,
            model_path / settings.MODEL_FILENAME,
        )

        print(
            f"Model saved to "
            f"{model_path / settings.MODEL_FILENAME}"
        )

        return accuracy