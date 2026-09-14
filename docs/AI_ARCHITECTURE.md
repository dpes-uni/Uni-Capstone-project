# AI Architecture

# Overview

This document describes the architecture of the AI module used in the **AI-Assisted Anomaly Detection and Adaptive MFA Identity & Document Verification Platform**.

The AI module is responsible for assessing login risk and assisting the authentication process by combining:

- Rule-based security analysis
- Machine learning predictions

AI acts as an independent service that receives login information, evaluates the risk, and returns a recommendation that the backend can use when deciding whether to allow a login or require additional verification.

---

# AI Module Responsibilities

The AI module performs the following tasks:

- Analyse login attempts
- Detect potentially suspicious behaviour
- Predict login risk using Machine Learning
- Support adaptive MFA decisions
- Record authentication events for auditing
- Generate and train AI datasets

Future versions will also support continuous session monitoring after a user has successfully logged in.

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

```
ai/
│
├── data/
│   ├── source/
│   │   └── platform_users.csv
│   │
│   ├── raw/
│   │   └── login_attempts.csv
│   │
│   └── processed/
│
├── models/
│   └── trained/
│       └── login_risk_model.pkl
│
├── scripts/
│   ├── generate_login_dataset.py
│   ├── train_login_model.py
│   └── predict.py
│
├── src/
│   ├── config/
│   ├── models/
│   ├── services/
│   └── utils/
│
└── .venv/
```

The **src** folder contains the production code used by the application.

The **scripts** folder contains development tools such as dataset generation, model training and testing.

---

# AI Workflow

The AI follows the workflow below.

```
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

Each component has a single responsibility, making the system easier to maintain and test.

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

The Predictor loads the trained Machine Learning model and predicts the login risk based on the login information.

The predictor only performs AI predictions.

It does not make authentication decisions.

---

## DecisionEngine

The Decision Engine combines:

- Rule-Based Risk Assessment
- Machine Learning Prediction

It produces a single final RiskResult that will later be returned to the Node.js backend.

---

## ModelTrainer

Responsible for training the Machine Learning model.

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

The project does not rely on external datasets.

Instead, it generates its own realistic login history.

The process is:

```
platform_users.csv
        │
        ▼
generate_login_dataset.py
        │
        ▼
login_attempts.csv
        │
        ▼
Model Training
```

This ensures the training data matches the business rules of the application.

---

# Machine Learning

Current Machine Learning Algorithm:

- Random Forest Classifier

Training Dataset:

- login_attempts.csv

Current Prediction Output:

- Low Risk
- Medium Risk
- High Risk

The trained model is saved as:

```
models/trained/login_risk_model.pkl
```

---

# Integration with Node.js

The Node.js backend communicates with the AI module through the `predict.py` script.

The integration process is:

```
Node.js

↓

JSON Input

↓

predict.py

↓

Predictor

↓

Decision Engine

↓

JSON Output

↓

Node.js
```

The backend never imports Python code directly.

This keeps both systems independent and easier to maintain.

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

The current implementation focuses on login risk assessment.

Future enhancements may include:

- Continuous session monitoring
- Additional anomaly detection techniques
- Behavioural profiling
- Impossible travel detection
- Additional AI models

These improvements are intentionally deferred until after the core system is complete to avoid unnecessary scope creep.

---

# Summary

The AI module has been designed as an independent, reusable service that supports adaptive authentication for the Identity & Document Verification Platform.

Its modular architecture separates rule-based security analysis, machine learning prediction, and decision making into individual components, making the system easier to maintain, test and integrate with the rest of the application.