"""
REST API wrapper for the AI-Assisted Anomaly Detection System.
Provides HTTP endpoints for integration with the Node.js backend.
"""

from flask import Flask, request, jsonify
from models.login_attempt import LoginAttempt
from services.risk_calculator import RiskCalculator
from services.predictor import Predictor
from services.decision_engine import DecisionEngine
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize services
risk_calculator = RiskCalculator()
predictor = Predictor()
decision_engine = DecisionEngine()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'ai-anomaly-detection',
        'timestamp': str(__import__('datetime').datetime.now())
    }), 200

@app.route('/predict', methods=['POST'])
def predict_risk():
    """
    Predict risk score for a login attempt.

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
    """
    try:
        # Get JSON data from request
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        # Create LoginAttempt object
        login = LoginAttempt.from_dict(data)

        # Validate the login attempt
        login.validate()

        # Calculate rule-based risk
        rule_result = risk_calculator.calculate(login)

        # Get AI prediction
        ai_result = predictor.predict(login)

        # Combine results using decision engine
        final_result = decision_engine.evaluate(rule_result, ai_result)

        # Log the request (without sensitive data)
        logger.info(f"Risk assessment for {login.username}: score={final_result.risk_score}, level={final_result.risk_level.value}")

        # Return result
        return jsonify(final_result.to_dict()), 200

    except ValueError as e:
        logger.warning(f"Validation error: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error in risk prediction: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/score', methods=['POST'])
def score_risk():
    """Alias for /predict endpoint."""
    return predict_risk()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)