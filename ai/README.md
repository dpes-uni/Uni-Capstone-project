# AI Module

The AI service provides login-risk and active-session risk predictions. It is implemented in Python with Flask and scikit-learn. The Node.js backend calls it over HTTP; authentication, OTP, re-authentication and session enforcement remain backend responsibilities.

## Main files

- `src/api.py` — Flask API (`127.0.0.1:8000`).
- `src/services/risk_calculator.py` — rule-based login assessment.
- `src/services/predictor.py` and `src/services/feature_engineer.py` — login model prediction and features.
- `src/services/session_predictor.py` — session model prediction.
- `src/services/decision_engine.py` — combines login rule and ML results and formats session results.
- `src/services/model_trainer.py` — login-model training.
- `scripts/generate_login_dataset.py` and `scripts/generate_session_dataset.py` — generate synthetic training data.
- `scripts/train_login_model.py` and `scripts/train_session_model.py` — train and save the models.
- `scripts/evaluate_models.py` — evaluates saved models against the available synthetic datasets.
- `data/source/platform_users.csv` — user profiles used to generate synthetic events.
- `data/raw/login_attempts.csv` and `data/raw/session_events.csv` — training datasets.
- `models/trained/` — trained model files: `login_risk_model.pkl` and `session_risk_model.pkl`.

## Models and data

The model uses 11 features: `login_hour`, `failed_login_attempts`, `new_device`, `vpn_detected`, `trusted_device`, `trusted_location`, `country`, `city`, `device`, `browser` and `operating_system`.

The session model predicts the Boolean `unusual_activity` label, with 402 `False` and 98 `True` labels in the current file. Its training features are `user_role`, `session_duration_minutes`, `documents_viewed`, `documents_downloaded`, `documents_uploaded`, `verification_actions`, `failed_actions` and `rapid_actions`. `username` is excluded. The target is excluded from model input.

Both use Random Forest classifiers and a stratified 80/20 train/test split with `random_state=42`. The login model uses 100 trees and one-hot encodes categorical fields. The session model uses 100 trees, one-hot encodes `user_role`, and balances classes. The session model is binary and returns Low or High risk; it does not predict Medium.


## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Health check. |
| `POST` | `/predict` | Login-risk prediction. Requires 13 fields: `username`, `device`, `browser`, `operating_system`, `ip_address`, `country`, `city`, `login_hour`, `failed_login_attempts`, `new_device`, `vpn_detected`, `trusted_device`, `trusted_location`. |
| `POST` | `/score` | Backwards-compatible alias for `/predict`. |
| `POST` | `/predict-session` | Session-risk prediction. Requires the 10 `SessionEvent` fields, including `unusual_activity` for interface compatibility; the predictor removes that target before making its prediction. `context_changes` is optional. |

The API's required payload fields are not all ML features. For example, login `username` and `ip_address` are required by the API, but the trained login model does not use them. For session prediction, `username` and `unusual_activity` are not model features, and `context_changes` is not part of the training feature set.

## Run locally

Run these commands from the `ai/` directory. Train the models before starting the API.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
python -m pip install -r requirements.txt

python scripts/generate_login_dataset.py
python scripts/generate_session_dataset.py
python scripts/train_login_model.py
python scripts/train_session_model.py
python src/api.py
```

In a separate terminal, from `ai/`, run the evaluation script with the trained models:

```bash
python scripts/evaluate_models.py
```

