"""
train_session_model.py

Trains the Session Monitoring Machine Learning model.

Input:
    data/raw/session_events.csv

Output:
    models/trained/session_risk_model.pkl

The model predicts whether an authenticated session
contains unusual activity.
"""

import sys
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


# ----------------------------------------------------------
# Project Paths
# ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "session_events.csv"
)

MODEL_DIR = (
    PROJECT_ROOT
    / "models"
    / "trained"
)

MODEL_FILE = MODEL_DIR / "session_risk_model.pkl"


# ----------------------------------------------------------
# Training Configuration
# ----------------------------------------------------------

TEST_SIZE = 0.20
RANDOM_STATE = 42


# ----------------------------------------------------------
# Main Training Function
# ----------------------------------------------------------

def train_model():

    print("=" * 60)
    print(" Session Monitoring AI Model Trainer")
    print("=" * 60)

    # ------------------------------------------------------
    # Load dataset
    # ------------------------------------------------------

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {DATA_FILE}"
        )

    dataframe = pd.read_csv(DATA_FILE)

    print(f"\nDataset loaded: {len(dataframe)} records")

    # ------------------------------------------------------
    # Define target
    # ------------------------------------------------------

    target_column = "unusual_activity"

    X = dataframe.drop(columns=[target_column])
    y = dataframe[target_column]

    # ------------------------------------------------------
    # Remove username
    #
    # Username identifies the user but should not be used
    # as a behavioural ML feature.
    # ------------------------------------------------------

    if "username" in X.columns:
        X = X.drop(columns=["username"])

    # ------------------------------------------------------
    # Define feature types
    # ------------------------------------------------------

    categorical_features = [
        "user_role"
    ]

    numerical_features = [
        "session_duration_minutes",
        "documents_viewed",
        "documents_downloaded",
        "documents_uploaded",
        "verification_actions",
        "failed_actions",
    ]

    boolean_features = [
        "rapid_actions"
    ]

    # ------------------------------------------------------
    # Convert boolean values to integers
    # ------------------------------------------------------

    for column in boolean_features:
        X[column] = X[column].astype(int)

    # ------------------------------------------------------
    # Preprocessing
    # ------------------------------------------------------

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "role",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_features,
            ),
            (
                "numeric",
                "passthrough",
                numerical_features,
            ),
            (
                "boolean",
                "passthrough",
                boolean_features,
            ),
        ]
    )

    # ------------------------------------------------------
    # Machine Learning Model
    # ------------------------------------------------------

    classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )

    pipeline = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor,
            ),
            (
                "classifier",
                classifier,
            ),
        ]
    )

    # ------------------------------------------------------
    # Train/Test Split
    # ------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"Training records : {len(X_train)}")
    print(f"Testing records  : {len(X_test)}")

    # ------------------------------------------------------
    # Train Model
    # ------------------------------------------------------

    print("\nTraining model...")

    pipeline.fit(
        X_train,
        y_train,
    )

    # ------------------------------------------------------
    # Evaluate Model
    # ------------------------------------------------------

    predictions = pipeline.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    print("\nModel Evaluation")
    print("-" * 60)

    print(
        f"Accuracy: {accuracy:.2%}"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Normal",
                "Unusual",
            ],
            zero_division=0,
        )
    )

    # ------------------------------------------------------
    # Save Model
    # ------------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        pipeline,
        MODEL_FILE,
    )

    print("-" * 60)
    print("Training completed successfully!")

    print(
        f"Model saved to: {MODEL_FILE}"
    )


# ----------------------------------------------------------
# Entry Point
# ----------------------------------------------------------

def main():

    try:
        train_model()

    except Exception as error:

        print(
            "\nTraining failed."
        )

        print(
            f"Error: {error}"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()