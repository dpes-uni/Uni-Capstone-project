"""
retrain_from_real.py

Retrains the login risk model using real exported data,
supplemented by synthetic data if real data is insufficient.

Usage:
    python scripts/retrain_from_real.py

Reads:
    data/real/login_attempts_real.csv  (exported from MongoDB)
    data/raw/login_attempts.csv        (original synthetic data)

Writes:
    models/trained/login_risk_model_v2.pkl
"""

import sys
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SYNTHETIC_FILE = PROJECT_ROOT / "data" / "raw" / "login_attempts.csv"
REAL_FILE = PROJECT_ROOT / "data" / "real" / "login_attempts_real.csv"
MODEL_DIR = PROJECT_ROOT / "models" / "trained"
OUTPUT_FILE = MODEL_DIR / "login_risk_model_v2.pkl"
ORIGINAL_MODEL = MODEL_DIR / "login_risk_model.pkl"

MIN_REAL_RECORDS = 50
RANDOM_STATE = 42
TEST_SIZE = 0.20

CATEGORICAL_FEATURES = [
    "country",
    "city",
    "device",
    "browser",
    "operating_system",
]

NUMERICAL_FEATURES = [
    "login_hour",
    "failed_login_attempts",
    "new_device",
    "vpn_detected",
    "trusted_device",
    "trusted_location",
]


def load_data():
    frames = []
    real_count = 0

    if REAL_FILE.exists():
        real_df = pd.read_csv(REAL_FILE)
        real_count = len(real_df)
        print(f"Real data:      {real_count} records")
        frames.append(real_df)
    else:
        print("Real data:      0 records (file not found)")

    if SYNTHETIC_FILE.exists():
        synth_df = pd.read_csv(SYNTHETIC_FILE)
        print(f"Synthetic data: {len(synth_df)} records")
        frames.append(synth_df)
    else:
        print("Synthetic data: 0 records (file not found)")

    if not frames:
        raise FileNotFoundError("No training data found")

    combined = pd.concat(frames, ignore_index=True)
    print(f"Combined:       {len(combined)} records")

    return combined, real_count


def train_model(df, label):
    print(f"\n{'=' * 60}")
    print(f" Training: {label}")
    print(f"{'=' * 60}")

    X = df.drop(columns=["risk_level"])
    y = df["risk_level"]

    # Drop non-feature columns
    for col in ["username", "risk_score", "recommended_action", "reason", "organisation", "user_role"]:
        if col in X.columns:
            X = X.drop(columns=[col])

    preprocessor = ColumnTransformer(
        transformers=[
            ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
            ("numerical", "passthrough", NUMERICAL_FEATURES),
        ]
    )

    classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        ]
    )

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"Training records: {len(X_train)}")
    print(f"Testing records:  {len(X_test)}")

    # Cross-validation (5-fold)
    print("\nRunning 5-fold cross-validation...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring="accuracy")
    print(f"CV Accuracy: {cv_scores.mean():.2%} (+/- {cv_scores.std():.2%})")

    # Final training
    print("\nTraining final model...")
    pipeline.fit(X_train, y_train)

    # Evaluation
    predictions = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\nTest Accuracy: {accuracy:.2%}")
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    return pipeline, accuracy


def main():
    print("=" * 60)
    print(" Login Risk Model Retrainer (Real Data)")
    print("=" * 60)

    # Load data
    df, real_count = load_data()

    if real_count < MIN_REAL_RECORDS:
        print(f"\nWarning: Only {real_count} real records (minimum {MIN_REAL_RECORDS} recommended)")
        print("Proceeding with combined synthetic + real data.")

    # Train new model
    new_pipeline, new_accuracy = train_model(df, "Real + Synthetic Data")

    # Train synthetic-only model for comparison
    if SYNTHETIC_FILE.exists():
        synth_df = pd.read_csv(SYNTHETIC_FILE)
        _, synth_accuracy = train_model(synth_df, "Synthetic Data Only (baseline)")
    else:
        synth_accuracy = None

    # Load original model accuracy if available
    original_accuracy = None
    if ORIGINAL_MODEL.exists():
        print(f"\nOriginal model exists at: {ORIGINAL_MODEL}")
        print("(Original accuracy not stored — compare manually by re-running train_login_model.py)")

    # Save new model
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(new_pipeline, OUTPUT_FILE)

    print(f"\n{'=' * 60}")
    print(" Results Summary")
    print(f"{'=' * 60}")
    print(f"New model (real+synthetic): {new_accuracy:.2%}")
    if synth_accuracy is not None:
        print(f"Baseline (synthetic only):  {synth_accuracy:.2%}")
    print(f"\nModel saved to: {OUTPUT_FILE}")

    if new_accuracy > (synth_accuracy or 0):
        print("\nNew model performs BETTER than synthetic baseline.")
        print(f"To deploy: copy {OUTPUT_FILE} -> {ORIGINAL_MODEL}")
    elif synth_accuracy and new_accuracy < synth_accuracy:
        print("\nNew model performs WORSE than synthetic baseline.")
        print("Consider collecting more real data before deploying.")
    else:
        print("\nNew model performs comparably to synthetic baseline.")

    print("\nTo swap in the new model:")
    print(f"  cp {OUTPUT_FILE} {ORIGINAL_MODEL}")
    print("  Then restart the AI service.")


if __name__ == "__main__":
    main()
