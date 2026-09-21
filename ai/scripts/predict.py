"""
predict.py

Loads the trained Login Risk AI model and predicts
the risk level for a login attempt.


"""

import json
import sys
from pathlib import Path

# ----------------------------------------------------------
# Make src importable
# ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

# ----------------------------------------------------------

from models.login_attempt import LoginAttempt
from services.predictor import Predictor


def load_demo_login() -> LoginAttempt:
    """
    Create a sample login attempt for testing.
    """

    return LoginAttempt(
        username="student1@example.com",
        device="Windows Laptop",
        browser="Microsoft Edge",
        operating_system="Windows 11",
        ip_address="203.15.44.18",
        country="Australia",
        city="Melbourne",
        login_hour=10,
        failed_login_attempts=0,
        new_device=False,
        vpn_detected=False,
        trusted_device=True,
        trusted_location=True,
    )


def load_json_login(json_file: str) -> LoginAttempt:
    """
    Read a LoginAttempt from a JSON file.
    """

    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    return LoginAttempt.from_dict(data)


def main():

    predictor = Predictor()

    # ------------------------------------------------------
    # JSON Mode
    # ------------------------------------------------------

    if len(sys.argv) == 2:

        login = load_json_login(sys.argv[1])

        result = predictor.predict(login)

        print(json.dumps(result.to_dict(), indent=4))

        return

    # ------------------------------------------------------
    # Demo Mode
    # ------------------------------------------------------

    print("=" * 60)
    print(" Login Risk Prediction Test")
    print("=" * 60)

    login = load_demo_login()

    result = predictor.predict(login)

    print("\nPrediction Result")
    print("-" * 60)

    print(f"Risk Score        : {result.risk_score}")
    print(f"Risk Level        : {result.risk_level.value}")
    print(f"Recommended Action: {result.recommended_action.value}")
    print(f"Reason            : {result.reason}")


if __name__ == "__main__":
    main()