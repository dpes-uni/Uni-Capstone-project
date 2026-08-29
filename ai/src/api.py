"""
api.py

Flask REST API for the Assure Docs AI Risk Engine.

Endpoints:

    GET  /health
        Health check for the Node.js backend.

    POST /predict
        Login risk assessment.

        Workflow:

            Node.js Backend
                  |
                  | JSON
                  v
            LoginAttempt
                  |
             ┌────┴────┐
             ▼         ▼
        Rule Risk    Login ML
             │         │
             └────┬────┘
                  ▼
          DecisionEngine
          evaluate_login()
                  │
                  ▼
              RiskResult
                  │
                  ▼
            Node.js Backend


    POST /predict-session
        Active-session risk assessment.

        Workflow:

            Node.js Backend
                  |
                  | JSON
                  v
             SessionEvent
                  |
                  ▼
           SessionPredictor
                  |
                  ▼
          DecisionEngine
          evaluate_session()
                  |
                  ▼
              RiskResult
                  |
                  ▼
            Node.js Backend


    POST /score
        Backwards-compatible alias for /predict.

Important architecture boundary:

    Python AI:
        Calculates and assesses risk.

    Node.js Backend:
        Enforces authentication, MFA, re-authentication,
        session termination and authorization decisions.

The Python service does NOT directly issue OTPs,
create sessions, log users out, or modify authentication state.
"""

from flask import Flask, jsonify, request
import logging

from models.login_attempt import LoginAttempt
from models.session_event import SessionEvent

from services.risk_calculator import RiskCalculator
from services.predictor import Predictor
from services.session_predictor import SessionPredictor
from services.decision_engine import DecisionEngine


# ==========================================================
# APPLICATION
# ==========================================================

app = Flask(__name__)


# ==========================================================
# LOGGING
# ==========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(__name__)


# ==========================================================
# AI SERVICES
# ==========================================================

risk_calculator = RiskCalculator()
predictor = Predictor()
session_predictor = SessionPredictor()
decision_engine = DecisionEngine()


# ==========================================================
# HEALTH CHECK
# ==========================================================

@app.route("/health", methods=["GET"])
def health():
    """
    Health check used by the Node.js backend.

    Returns:
        200 if the AI service is running.
    """

    return jsonify({
        "status": "healthy",
        "service": "assure-docs-ai",
    }), 200


# ==========================================================
# LOGIN RISK PREDICTION
# ==========================================================

@app.route("/predict", methods=["POST"])
def predict_risk():
    """
    Predict login risk.

    Expected JSON payload:

    {
        "username": "string",
        "device": "string",
        "browser": "string",
        "operating_system": "string",
        "ip_address": "string",
        "country": "string",
        "city": "string",
        "login_hour": 0-23,
        "failed_login_attempts": integer >= 0,
        "new_device": boolean,
        "vpn_detected": boolean,
        "trusted_device": boolean,
        "trusted_location": boolean
    }

    Returns:

    {
        "risk_score": integer,
        "risk_level": "Low|Medium|High",
        "recommended_action":
            "Allow Login"
            | "Require Email OTP"
            | "Require Additional Verification"
            | "Block Login",
        "reason": "string"
    }
    """

    try:

        # --------------------------------------------------
        # 1. Read JSON request
        # --------------------------------------------------

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "error": "No valid JSON object provided"
            }), 400


        # --------------------------------------------------
        # 2. Validate required fields
        # --------------------------------------------------

        required_fields = [
            "username",
            "device",
            "browser",
            "operating_system",
            "ip_address",
            "country",
            "city",
            "login_hour",
            "failed_login_attempts",
            "new_device",
            "vpn_detected",
            "trusted_device",
            "trusted_location",
        ]

        missing_fields = [
            field
            for field in required_fields
            if field not in data
        ]

        if missing_fields:
            return jsonify({
                "error": "Missing required fields",
                "fields": missing_fields,
            }), 400


        # --------------------------------------------------
        # 3. Create LoginAttempt
        # --------------------------------------------------

        login = LoginAttempt.from_dict(data)


        # --------------------------------------------------
        # 4. Validate LoginAttempt
        # --------------------------------------------------

        login.validate()


        # --------------------------------------------------
        # 5. Rule-Based Risk
        # --------------------------------------------------

        rule_result = risk_calculator.calculate(login)


        # --------------------------------------------------
        # 6. Login Machine Learning Risk
        # --------------------------------------------------

        login_ai_result = predictor.predict(login)


        # --------------------------------------------------
        # 7. Login Decision
        #
        # Session risk is NOT included here.
        #
        # A login request occurs before the authenticated
        # session exists.
        # --------------------------------------------------

        final_login_result = decision_engine.evaluate_login(
            rule_result,
            login_ai_result,
        )


        # --------------------------------------------------
        # 8. Build response
        # --------------------------------------------------

        response = {
            "risk_score": final_login_result.risk_score,
            "risk_level": final_login_result.risk_level.value,
            "recommended_action": (
                final_login_result
                .recommended_action
                .value
            ),
            "reason": final_login_result.reason,
        }


        # --------------------------------------------------
        # 9. Logging
        # --------------------------------------------------

        logger.info(
            "Login risk assessment completed: "
            "user=%s level=%s score=%s action=%s",
            login.username,
            response["risk_level"],
            response["risk_score"],
            response["recommended_action"],
        )


        # --------------------------------------------------
        # 10. Return
        # --------------------------------------------------

        return jsonify(response), 200


    except ValueError as error:

        logger.warning(
            "Invalid login risk request: %s",
            str(error),
        )

        return jsonify({
            "error": str(error),
        }), 400


    except KeyError as error:

        logger.warning(
            "Invalid login risk request - missing field: %s",
            str(error),
        )

        return jsonify({
            "error": "Invalid request data",
            "field": str(error),
        }), 400


    except FileNotFoundError as error:

        logger.error(
            "Login AI model unavailable: %s",
            str(error),
        )

        return jsonify({
            "error": "AI model unavailable",
        }), 500


    except Exception:

        logger.exception(
            "Unexpected error during login risk prediction"
        )

        return jsonify({
            "error": "Internal server error",
        }), 500


# ==========================================================
# ACTIVE SESSION RISK PREDICTION
# ==========================================================

@app.route("/predict-session", methods=["POST"])
def predict_session_risk():
    """
    Predict risk for an already-authenticated session.

    Expected JSON payload is based on SessionEvent.

    Example:

    {
        "username": "student1@example.com",
        "user_role": "Student",
        "session_duration_minutes": 20,
        "documents_viewed": 3,
        "documents_downloaded": 1,
        "documents_uploaded": 1,
        "verification_actions": 2,
        "failed_actions": 0,
        "rapid_actions": false,
        "unusual_activity": false
    }

    Note:

        unusual_activity is retained for compatibility with
        the existing SessionEvent/training interface.

        SessionPredictor removes the target field before
        making the ML prediction.

    Returns:

    {
        "risk_score": integer,
        "risk_level": "Low|Medium|High",
        "recommended_action":
            "Allow Login"
            | "Require Email OTP"
            | "Require Additional Verification"
            | "Block Login",
        "reason": "string"
    }
    """

    try:

        # --------------------------------------------------
        # 1. Read JSON request
        # --------------------------------------------------

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "error": "No valid JSON object provided"
            }), 400


        # --------------------------------------------------
        # 2. Validate required session fields
        # --------------------------------------------------

        required_fields = [
            "username",
            "user_role",
            "session_duration_minutes",
            "documents_viewed",
            "documents_downloaded",
            "documents_uploaded",
            "verification_actions",
            "failed_actions",
            "rapid_actions",
            "unusual_activity",
        ]

        missing_fields = [
            field
            for field in required_fields
            if field not in data
        ]

        if missing_fields:
            return jsonify({
                "error": "Missing required fields",
                "fields": missing_fields,
            }), 400


        # --------------------------------------------------
        # 3. Create SessionEvent
        # --------------------------------------------------

        session = SessionEvent.from_dict(data)


        # --------------------------------------------------
        # 4. Validate SessionEvent if supported
        # --------------------------------------------------

        validate_method = getattr(
            session,
            "validate",
            None,
        )

        if callable(validate_method):
            validate_method()


        # --------------------------------------------------
        # 5. Session Machine Learning Risk
        # --------------------------------------------------

        session_ai_result = session_predictor.predict(
            session
        )


        # --------------------------------------------------
        # 6. Session Decision
        #
        # No login risk is fabricated or reused here.
        #
        # The active-session decision is based on the
        # SessionPredictor result.
        # --------------------------------------------------

        final_session_result = (
            decision_engine.evaluate_session(
                session_ai_result
            )
        )


        # --------------------------------------------------
        # 7. Build response
        # --------------------------------------------------

        response = {
            "risk_score": final_session_result.risk_score,
            "risk_level": final_session_result.risk_level.value,
            "recommended_action": (
                final_session_result
                .recommended_action
                .value
            ),
            "reason": final_session_result.reason,
        }


        # --------------------------------------------------
        # 8. Logging
        # --------------------------------------------------

        logger.info(
            "Session risk assessment completed: "
            "user=%s level=%s score=%s action=%s",
            session.username,
            response["risk_level"],
            response["risk_score"],
            response["recommended_action"],
        )


        # --------------------------------------------------
        # 9. Return
        # --------------------------------------------------

        return jsonify(response), 200


    except ValueError as error:

        logger.warning(
            "Invalid session risk request: %s",
            str(error),
        )

        return jsonify({
            "error": str(error),
        }), 400


    except KeyError as error:

        logger.warning(
            "Invalid session risk request - missing field: %s",
            str(error),
        )

        return jsonify({
            "error": "Invalid request data",
            "field": str(error),
        }), 400


    except FileNotFoundError as error:

        logger.error(
            "Session AI model unavailable: %s",
            str(error),
        )

        return jsonify({
            "error": "Session AI model unavailable",
        }), 500


    except Exception:

        logger.exception(
            "Unexpected error during session risk prediction"
        )

        return jsonify({
            "error": "Internal server error",
        }), 500


# ==========================================================
# SCORE ALIAS
# ==========================================================

@app.route("/score", methods=["POST"])
def score_risk():
    """
    Alias for /predict.

    Kept for backwards compatibility with existing clients.
    """

    return predict_risk()


# ==========================================================
# APPLICATION ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8000,
        debug=False,
    )