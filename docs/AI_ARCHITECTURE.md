# AI Architecture

## Overview

This document describes the architecture of the AI module used in the **AI-Assisted Anomaly Detection and Adaptive MFA Identity & Document Verification Platform**.

The AI module is responsible for assessing login risk and assisting the authentication process by combining:

- Rule-based security analysis
- Machine learning predictions

AI operates as a separate service that receives login or session information, evaluates risk, and returns a recommendation that the backend uses when deciding whether to allow activity or require additional verification.

---

# AI Module Responsibilities

The AI module performs the following tasks:

- Analyse login attempts
- Detect potentially suspicious behaviour
- Predict login and session risk using Machine Learning
- Support adaptive MFA decisions
- Record authentication events for auditing
- Generate and train AI datasets

The system also supports session monitoring after login to identify suspicious activity and request re-authentication or additional verification when required.

---

# User Roles

The system currently supports three user roles:

- Student
- Agent
- Institution

Each role has different expected login behaviour.

For example:

- Students generally log in a few times per day using personal devices.
- Agents may log in frequently and are more likely to use VPN connections.
- Institutions generally log in during business hours from trusted corporate devices.

The AI uses these behavioural differences when generating datasets and predicting login risk.

---

# Folder Structure

```text
ai/
├── data/
│   ├── source/
│   │   └── platform_users.csv
│   ├── raw/
│   │   ├── login_attempts.csv
│   │   └── session_events.csv
│   └── processed/
├── models/
│   └── trained/
├── scripts/
│   ├── generate_login_dataset.py
│   ├── train_session_model.py
│   └── evaluate_models.py
├── src/
│   ├── api.py
│   ├── predictor.py
│   ├── config/
│   ├── models/
│   ├── services/
│   │   └── model_trainer.py
│   └── utils/
└── .venv/
```

The **src** folder contains the AI service, prediction and training components used by the application.

The **scripts** folder contains development tools for dataset generation, model training and evaluation.

---

# AI Workflow

The AI follows two workflows.

**Login risk assessment**

```text
Login Attempt
      │
      ▼
Risk Calculator
(Rule-Based)
      │
      ▼
Machine Learning Predictor
      │
      ▼
Decision Engine
      │
      ▼
Final Risk Result
      │
      ▼
Node.js Backend
```

**Session risk assessment**

```text
Session Activity
      │
      ▼
Session Risk Predictor
      │
      ▼
Backend Session Monitoring
      │
      ▼
Context and Accumulated Risk Checks
      │
      ▼
Continue Session or Require Verification
```

Each component has a specific responsibility, making the system easier to maintain and test.

---

# Core Components

## LoginAttempt

Represents a single login attempt received from the application.

It stores information such as:

- Username
- Device
- Browser
- Operating System
- IP Address
- Country
- City
- Login Time
- Failed Login Attempts
- VPN Status
- Trusted Device
- Trusted Location

---

## RiskCalculator

The Rule-Based Risk Calculator performs an initial security assessment using predefined business rules.

Examples include:

- New device
- VPN detected
- Multiple failed login attempts
- Untrusted location

The result is a RiskResult object.

---

## Predictor

The Predictor loads the trained login-risk Machine Learning model and predicts risk based on login information.

The predictor performs AI predictions but does not make authentication decisions independently.

---

## DecisionEngine

The Decision Engine combines:

- Rule-Based Risk Assessment
- Machine Learning Prediction

It produces a single final RiskResult for the Node.js backend. The higher risk assessment takes precedence when the two assessments differ.

---

## SessionPredictor

The SessionPredictor uses a separate Random Forest model to identify unusual session activity based on information such as session duration, document activity, failed actions and rapid activity.

It returns a session-risk result that the backend can use when evaluating whether additional verification is needed.

---

## SessionMonitor

The SessionMonitor in the Node.js backend monitors active sessions by comparing session context, tracking accumulated risk and applying risk thresholds.

It can require re-authentication or step-up verification when suspicious activity or sensitive actions meet the relevant risk thresholds.

---

## ModelTrainer

Responsible for training the Machine Learning models.

Tasks include:

- Loading the dataset
- Feature processing
- Model training
- Model evaluation
- Saving the trained model

---

## FeatureEngineer

Converts LoginAttempt objects into machine learning features.

This separates business objects from AI processing and keeps the code easier to maintain.

---

## AuditLogger

Records authentication events for auditing and future forensic analysis.

The logger stores:

- Login details
- Rule-based assessment
- AI prediction
- Final authentication decision

---

# Dataset Generation

The project does not rely on external training datasets. Instead, it generates synthetic login and session data for model training.

The login dataset generation process is:

```text
platform_users.csv
        │
        ▼
generate_login_dataset.py
        │
        ▼
login_attempts.csv
        │
        ▼
Login Model Training
```

A separate `session_events.csv` dataset is used to train the Session Risk Model.

Both datasets contain 500 records. As the data is synthetic, the results require further validation using representative, independently labelled data.

---

# Machine Learning

Current Machine Learning Algorithm:

- Random Forest Classifier

Training Datasets:

- `login_attempts.csv`
- `session_events.csv`

Current Login Model Output:

- Low Risk
- High Risk

The login model is trained on Low- and High-risk labels only. Medium risk can still be identified by the rule-based assessment and combined decision process.

The Session Risk Model predicts:

- Normal Activity
- Unusual Activity

The trained models are saved under:

```text
models/trained/
```

---

# Integration with Node.js

The Node.js backend communicates with the AI module through a **Python Flask API**, rather than executing `predict.py` directly.

The integration process is:

```text
Node.js Backend
       │
       ▼
HTTP Request
       │
       ▼
Python Flask API
       │
       ▼
Risk Prediction
       │
       ▼
JSON Response
       │
       ▼
Node.js Backend
```

The API provides the following endpoints:

- `GET /health` — Checks service health.
- `POST /predict` — Predicts login risk.
- `POST /score` — Alternative endpoint for login-risk prediction.
- `POST /predict-session` — Predicts session risk.

The backend never imports Python code directly. This keeps both systems independent and easier to maintain.

---

# Development Principles

The AI module follows the following design principles:

- Single Responsibility Principle
- Separation of Concerns
- Reusable Components
- Modular Design
- Simple and Maintainable Code

The objective is to produce a professional but achievable architecture suitable for a university capstone project.

---

# Future Improvements

Further improvements may include:

- Additional anomaly detection techniques
- Behavioural profiling
- Impossible travel detection
- Additional AI models

These improvements can be considered after evaluating the current implementation.

---

# Summary

The AI module supports adaptive authentication through rule-based login assessment, machine learning predictions and session monitoring. Its components remain separate from the Node.js backend, which combines risk results with security controls to determine when additional verification is required.