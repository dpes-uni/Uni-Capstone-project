"""
main.py

Entry point for the AI-Assisted Anomaly Detection System.

Workflow:
1. Receive login request
2. Create LoginAttempt object
3. Calculate rule-based risk
4. Run AI prediction
5. Return final result
"""

from models.login_attempt import LoginAttempt
from services.risk_calculator import RiskCalculator
from services.predictor import Predictor


def main():
    """Main application workflow."""

    # Create login attempt from incoming data
    login = LoginAttempt.from_input()

    # Calculate rule-based risk
    risk_calculator = RiskCalculator()
    rule_result = risk_calculator.calculate(login)

    # AI prediction
    predictor = Predictor()
    final_result = predictor.predict(login, rule_result)

    # Return result
    print(final_result.to_json())


if __name__ == "__main__":
    main()