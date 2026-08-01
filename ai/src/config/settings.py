"""
settings.py

Central configuration for the AI-Assisted Anomaly Detection System.

All configurable values should be stored here.
"""

# ==========================================================
# Risk Score Thresholds
# ==========================================================

LOW_RISK_MAX = 30
MEDIUM_RISK_MAX = 60
HIGH_RISK_MAX = 100


# ==========================================================
# Risk Points
# ==========================================================

NEW_DEVICE_POINTS = 20

NEW_LOCATION_POINTS = 30

VPN_POINTS = 15

FAILED_LOGIN_POINTS = 25

OUTSIDE_BUSINESS_HOURS_POINTS = 10


# ==========================================================
# Login Rules
# ==========================================================

MAX_FAILED_LOGIN_ATTEMPTS = 3

BUSINESS_START_HOUR = 8
BUSINESS_END_HOUR = 18


# ==========================================================
# Model Configuration
# ==========================================================

MODEL_FILENAME = "risk_model.pkl"


# ==========================================================
# Dataset Configuration
# ==========================================================

RAW_DATASET = "data/raw/login_attempts.csv"

PROCESSED_DATASET = "data/processed/processed_login_attempts.csv"


# ==========================================================
# Logging
# ==========================================================

LOG_FILE = "logs/ai_log.txt"