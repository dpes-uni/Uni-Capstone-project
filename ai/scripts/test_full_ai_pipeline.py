"""
test_full_ai_pipeline.py

Tests the complete AI/ML decision pipeline:

    LoginAttempt
        |
        +--> Rule-Based Risk Calculator
        |
        +--> Login ML Predictor
        |
        +--> Session ML Predictor
                    |
                    v
              DecisionEngine
                    |
                    v
              Final RiskResult

Test scenarios:
1. Trusted login + normal session
2. Normal login + unusual session
3. Suspicious login + normal session
"""

import sys
from pathlib import Path


# ==========================================================
# PROJECT PATH
# ==========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))


# ==========================================================
# IMPORTS
# ==========================================================

from models.login_attempt import LoginAttempt
from models.session_event import SessionEvent

from services.risk_calculator import RiskCalculator
from services.predictor import Predictor
from services.session_predictor import SessionPredictor
from services.decision_engine import DecisionEngine


# ==========================================================
# DISPLAY RESULT
# ==========================================================

def print_result(test_name, result):
    """
    Display the final RiskResult in a readable format.
    """

    print(f"\n===== {test_name} =====")

    print(
        f"Risk Score         : "
        f"{result.risk_score}"
    )

    print(
        f"Risk Level         : "
        f"{result.risk_level.value}"
    )

    print(
        f"Recommended Action : "
        f"{result.recommended_action.value}"
    )

    print(
        f"Reason             : "
        f"{result.reason}"
    )


# ==========================================================
# RUN PIPELINE
# ==========================================================

def run_pipeline(
    test_name,
    login,
    session,
):
    """
    Run one complete AI/ML risk assessment.

    Pipeline:

        LoginAttempt
             |
        +----+------------------+
        |                       |
        v                       v
    RiskCalculator          Predictor
        |                       |
        +-----------+-----------+
                    |
                    |
              SessionPredictor
                    |
                    v
              DecisionEngine
                    |
                    v
             Final RiskResult
    """

    # ------------------------------------------------------
    # Initialise services
    # ------------------------------------------------------

    risk_calculator = RiskCalculator()
    login_predictor = Predictor()
    session_predictor = SessionPredictor()
    decision_engine = DecisionEngine()

    # ------------------------------------------------------
    # Validate Login
    # ------------------------------------------------------

    login.validate()

    # ------------------------------------------------------
    # 1. Rule-Based Login Risk
    # ------------------------------------------------------

    rule_result = risk_calculator.calculate(
        login
    )

    # ------------------------------------------------------
    # 2. Login Machine Learning Risk
    # ------------------------------------------------------

    login_ai_result = login_predictor.predict(
        login
    )

    # ------------------------------------------------------
    # 3. Session Machine Learning Risk
    #
    # SessionPredictor now returns RiskResult directly.
    # No conversion or temporary dictionary is required.
    # ------------------------------------------------------

    session_ai_result = session_predictor.predict(
        session
    )

    # ------------------------------------------------------
    # 4. Combine All Risk Assessments
    # ------------------------------------------------------

    final_result = decision_engine.evaluate(
        rule_result,
        login_ai_result,
        session_ai_result,
    )

    # ------------------------------------------------------
    # 5. Display Final Result
    # ------------------------------------------------------

    print_result(
        test_name,
        final_result,
    )


# ==========================================================
# MAIN TESTS
# ==========================================================

def main():

    # ======================================================
    # TEST 1
    #
    # Trusted Login + Normal Session
    #
    # Expected:
    # Low Risk
    # Allow Login
    # ======================================================

    login = LoginAttempt(
        username="student1@example.com",
        device="Laptop",
        browser="Chrome",
        operating_system="Windows",
        ip_address="203.0.113.10",
        country="Australia",
        city="Sydney",
        login_hour=10,
        failed_login_attempts=0,
        new_device=False,
        vpn_detected=False,
        trusted_device=True,
        trusted_location=True,
    )

    session = SessionEvent(
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

    run_pipeline(
        "TEST 1 - Trusted Login + Normal Session",
        login,
        session,
    )

    # ======================================================
    # TEST 2
    #
    # Normal Login + Unusual Session
    #
    # Expected:
    # High Risk
    # Require Additional Verification
    # ======================================================

    login = LoginAttempt(
        username="student1@example.com",
        device="Laptop",
        browser="Chrome",
        operating_system="Windows",
        ip_address="203.0.113.10",
        country="Australia",
        city="Sydney",
        login_hour=10,
        failed_login_attempts=0,
        new_device=False,
        vpn_detected=False,
        trusted_device=True,
        trusted_location=True,
    )

    session = SessionEvent(
        username="student1@example.com",
        user_role="Student",
        session_duration_minutes=240,
        documents_viewed=40,
        documents_downloaded=15,
        documents_uploaded=8,
        verification_actions=20,
        failed_actions=5,
        rapid_actions=True,
        unusual_activity=False,
    )

    run_pipeline(
        "TEST 2 - Normal Login + Unusual Session",
        login,
        session,
    )

    # ======================================================
    # TEST 3
    #
    # Suspicious Login + Normal Session
    #
    # Expected:
    # High Risk
    # Strong Login Security Action
    # ======================================================

    login = LoginAttempt(
        username="student1@example.com",
        device="Unknown Device",
        browser="Unknown Browser",
        operating_system="Unknown",
        ip_address="198.51.100.50",
        country="Unknown",
        city="Unknown",
        login_hour=3,
        failed_login_attempts=5,
        new_device=True,
        vpn_detected=True,
        trusted_device=False,
        trusted_location=False,
    )

    session = SessionEvent(
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

    run_pipeline(
        "TEST 3 - Suspicious Login + Normal Session",
        login,
        session,
    )


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":
    main()