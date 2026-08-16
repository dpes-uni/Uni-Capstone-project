"""
predict_session.py

Loads the trained Session Monitoring AI model and predicts
whether an authenticated session contains unusual activity.

Supports:

1. Demo Mode
   python scripts/predict_session.py

2. JSON Mode
   python scripts/predict_session.py session.json
"""

import json
import sys
from pathlib import Path

# ==========================================================
# Integration Notes
#
# Demo Mode:
#     python scripts/predict_session.py
#
# JSON Mode:
#     python scripts/predict_session.py session.json
#
# The JSON mode is intended for future Node.js integration.
# ==========================================================


# ----------------------------------------------------------
# Make src importable
# ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

# ----------------------------------------------------------

from models.session_event import SessionEvent
from services.session_predictor import SessionPredictor


def load_demo_session() -> SessionEvent:
    """
    Create a sample normal session for testing.
    """

    return SessionEvent(
        username="student1@example.com",
        user_role="Student",
        session_duration_minutes=20,
        documents_viewed=3,
        documents_downloaded=1,
        documents_uploaded=1,
        verification_actions=2,
        failed_actions=0,
        rapid_actions=False,
        unusual_activity=False,
    )


def load_json_session(json_file: str) -> SessionEvent:
    """
    Load a SessionEvent from a JSON file.
    """

    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    return SessionEvent.from_dict(data)


def main():

    predictor = SessionPredictor()

    # ======================================================
    # JSON Mode
    # ======================================================

    if len(sys.argv) == 2:

        session = load_json_session(
            sys.argv[1]
        )

        result = predictor.predict(session)

        print(
            json.dumps(
                result,
                indent=4
            )
        )

        return

    # ======================================================
    # Demo Mode
    # ======================================================

    print("=" * 60)
    print(" Session Monitoring AI Prediction Test")
    print("=" * 60)

    session = load_demo_session()

    result = predictor.predict(session)

    print("\nPrediction Result")
    print("-" * 60)

    print(
        f"Unusual Activity : "
        f"{result['unusual_activity']}"
    )

    print(
        f"Risk Level       : "
        f"{result['risk_level']}"
    )

    print(
        f"Confidence       : "
        f"{result['confidence']}"
    )


if __name__ == "__main__":
    main()