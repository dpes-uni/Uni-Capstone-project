#!/usr/bin/env python3
"""
evaluate_models.py

Evaluates the trained login risk and session risk ML models
using the existing synthetic datasets. Does NOT retrain models.

Produces a report including:
- Model metrics (accuracy, precision, recall, F1, confusion matrix, FPR, FNR, ROC-AUC)
- Authentication/security metrics (all UNAVAILABLE - no independent ground truth)
- Limitations documentation

Usage:
    python scripts/evaluate_models.py          # Generate full report
    python scripts/evaluate_models.py --test  # Run metric function tests (JSON output)
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# ----------------------------------------------------------
# Project Paths
# ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

DATA_DIR = PROJECT_ROOT / "data" / "raw"
MODEL_DIR = PROJECT_ROOT / "models" / "trained"

# ----------------------------------------------------------
# Metric Calculation Functions
# ----------------------------------------------------------


def calculate_accuracy(y_true, y_pred):
    """Calculate accuracy: (TP+TN)/total."""
    return float(accuracy_score(y_true, y_pred))


def calculate_precision(y_true, y_pred, pos_label=None):
    """Calculate precision for the positive class. Returns None if undefined."""
    return _safe_sklearn_metric(precision_score, y_true, y_pred, pos_label=pos_label, zero_division=0)


def calculate_recall(y_true, y_pred, pos_label=None):
    """Calculate recall for the positive class. Returns None if undefined."""
    return _safe_sklearn_metric(recall_score, y_true, y_pred, pos_label=pos_label, zero_division=0)


def calculate_f1(y_true, y_pred, pos_label=None):
    """Calculate F1 for the positive class. Returns None if undefined."""
    return _safe_sklearn_metric(f1_score, y_true, y_pred, pos_label=pos_label, zero_division=0)


def _binary_cm(y_true, y_pred, pos_label=None):
    """Return (tp, fp, tn, fn) from a binary confusion matrix."""
    labels = _labels(y_true, pos_label)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    if cm.shape == (2, 2):
        # labels = [pos_label, other] → cm = [[TP, FN], [FP, TN]]
        tp, fn, fp, tn = cm.ravel()
        return tp, fp, tn, fn
    return None, None, None, None


def calculate_fpr(y_true, y_pred, pos_label=None):
    """Calculate False Positive Rate: FP/(FP+TN). Returns None if denominator is 0."""
    tp, fp, tn, fn = _binary_cm(y_true, y_pred, pos_label)
    if fp is None or (fp + tn) == 0:
        return None
    return float(fp / (fp + tn))


def calculate_fnr(y_true, y_pred, pos_label=None):
    """Calculate False Negative Rate: FN/(FN+TP). Returns None if denominator is 0."""
    tp, fp, tn, fn = _binary_cm(y_true, y_pred, pos_label)
    if fn is None or (fn + tp) == 0:
        return None
    return float(fn / (fn + tp))


def calculate_confusion_matrix(y_true, y_pred, labels=None):
    """Calculate confusion matrix as a nested list."""
    if labels is None:
        labels = sorted(set(y_true) | set(y_pred))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    return cm.tolist()


def calculate_roc_auc(y_true, y_scores, pos_label=None):
    """
    Calculate ROC-AUC using predict_proba outputs.

    Returns None if:
    - Only one class is present in y_true
    - y_scores is not available
    - Less than 2 classes in y_true

    If pos_label is provided and y_true contains non-numeric labels,
    y_true is converted to binary (1 for pos_label, 0 for other).
    """
    unique_true = set(y_true)
    if len(unique_true) < 2:
        return None
    # Convert string/non-binary labels to binary if pos_label provided
    if pos_label is not None and not all(isinstance(v, (int, float, np.integer, np.floating)) for v in y_true):
        y_binary = [1 if v == pos_label else 0 for v in y_true]
    else:
        y_binary = list(y_true)
    try:
        return float(roc_auc_score(y_binary, y_scores))
    except Exception:
        return None


def _safe_sklearn_metric(metric_fn, y_true, y_pred, pos_label=None, **kwargs):
    """Call a sklearn metric safely, returning None if undefined."""
    if len(set(y_true)) < 2:
        return None
    try:
        return float(metric_fn(y_true, y_pred, pos_label=pos_label, zero_division=0))
    except Exception:
        return None


def _labels(y_true, pos_label):
    """Return sorted unique labels, or [pos_label, other] pair."""
    if pos_label is not None:
        other = [x for x in sorted(set(y_true)) if x != pos_label]
        return [pos_label] + other if other else [pos_label]
    return sorted(set(y_true))


# ----------------------------------------------------------
# Model Evaluation Functions
# ----------------------------------------------------------


def evaluate_login_model():
    """Evaluate the login risk model on the full dataset."""
    model_path = MODEL_DIR / "login_risk_model.pkl"
    data_path = DATA_DIR / "login_attempts.csv"

    if not model_path.exists():
        return {"error": f"Model not found: {model_path}"}
    if not data_path.exists():
        return {"error": f"Dataset not found: {data_path}"}

    df = pd.read_csv(data_path)
    y_true = df["risk_level"].tolist()

    # Features matching FeatureEngineer.to_features output
    feature_cols = [
        "login_hour", "failed_login_attempts", "new_device", "vpn_detected",
        "trusted_device", "trusted_location", "country", "city",
        "device", "browser", "operating_system",
    ]
    X = df[feature_cols].copy()

    model = joblib.load(str(model_path))
    y_pred = model.predict(X)
    y_pred = [str(p) for p in y_pred]

    # Determine positive class: High (suspicious)
    positive_class = "High"
    pos_label = positive_class if positive_class in set(y_true) else None

    # ROC-AUC via predict_proba
    roc_auc = "UNAVAILABLE"
    roc_auc_reason = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        class_to_idx = {str(c): i for i, c in enumerate(model.classes_)}
        if pos_label and pos_label in class_to_idx and len(set(y_true)) >= 2:
            pos_proba = proba[:, class_to_idx[pos_label]]
            result = calculate_roc_auc(y_true, pos_proba, pos_label=pos_label)
            roc_auc = result if result is not None else "UNAVAILABLE"
            if result is None:
                roc_auc_reason = "ROC-AUC could not be computed"
        else:
            roc_auc_reason = "Positive class not found in model output classes"
    else:
        roc_auc_reason = "Model has no predict_proba method"

    cm = calculate_confusion_matrix(y_true, y_pred, labels=["Low", "High"])

    return {
        "model": "Login Risk Model",
        "dataset": "ai/data/raw/login_attempts.csv",
        "classes_present": sorted(set(y_true)),
        "class_distribution": {c: y_true.count(c) for c in sorted(set(y_true))},
        "positive_class": positive_class,
        "accuracy": calculate_accuracy(y_true, y_pred),
        "precision": calculate_precision(y_true, y_pred, pos_label=pos_label),
        "recall": calculate_recall(y_true, y_pred, pos_label=pos_label),
        "f1": calculate_f1(y_true, y_pred, pos_label=pos_label),
        "fpr": calculate_fpr(y_true, y_pred, pos_label=pos_label),
        "fnr": calculate_fnr(y_true, y_pred, pos_label=pos_label),
        "roc_auc": roc_auc,
        "roc_auc_unavailable_reason": roc_auc_reason,
        "confusion_matrix": cm,
        "labels": ["Low", "High"],
    }


def evaluate_session_model():
    """Evaluate the session risk model on the full dataset."""
    model_path = MODEL_DIR / "session_risk_model.pkl"
    data_path = DATA_DIR / "session_events.csv"

    if not model_path.exists():
        return {"error": f"Model not found: {model_path}"}
    if not data_path.exists():
        return {"error": f"Dataset not found: {data_path}"}

    df = pd.read_csv(data_path)
    y_true = df["unusual_activity"].tolist()
    y_true = [bool(v) for v in y_true]

    # Features matching session trainer preprocessing
    feature_cols = [
        "session_duration_minutes", "documents_viewed", "documents_downloaded",
        "documents_uploaded", "verification_actions", "failed_actions",
        "rapid_actions", "user_role",
    ]
    X = df[feature_cols].copy()
    X["rapid_actions"] = X["rapid_actions"].astype(int)

    model = joblib.load(str(model_path))
    y_pred = model.predict(X)
    y_pred = [bool(p) for p in y_pred]

    positive_class = True
    pos_label = True if True in set(y_true) else None

    # ROC-AUC via predict_proba
    roc_auc = "UNAVAILABLE"
    roc_auc_reason = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        class_to_idx = {str(c): i for i, c in enumerate(model.classes_)}
        # Handle boolean class labels
        true_key = str(True)
        false_key = str(False)
        if true_key in class_to_idx and pos_label is not None:
            # Find the column for True/positive
            for i, c in enumerate(model.classes_):
                if str(c) == true_key:
                    pos_proba = proba[:, i]
                    result = calculate_roc_auc([bool(t) for t in y_true], pos_proba)
                    roc_auc = result if result is not None else "UNAVAILABLE"
                    if result is None:
                        roc_auc_reason = "ROC-AUC could not be computed"
                    break
        else:
            roc_auc_reason = "Positive class not found in model output classes"
    else:
        roc_auc_reason = "Model has no predict_proba method"

    cm = calculate_confusion_matrix(
        [str(t) for t in y_true], [str(p) for p in y_pred],
        labels=["False", "True"],
    )

    return {
        "model": "Session Risk Model",
        "dataset": "ai/data/raw/session_events.csv",
        "classes_present": sorted(set([str(v) for v in y_true])),
        "class_distribution": {str(v): [str(t) for t in y_true].count(str(v)) for v in sorted(set(y_true))},
        "positive_class": "True",
        "accuracy": calculate_accuracy([str(t) for t in y_true], [str(p) for p in y_pred]),
        "precision": calculate_precision([str(t) for t in y_true], [str(p) for p in y_pred], pos_label="True"),
        "recall": calculate_recall([str(t) for t in y_true], [str(p) for p in y_pred], pos_label="True"),
        "f1": calculate_f1([str(t) for t in y_true], [str(p) for p in y_pred], pos_label="True"),
        "fpr": calculate_fpr([str(t) for t in y_true], [str(p) for p in y_pred], pos_label="True"),
        "fnr": calculate_fnr([str(t) for t in y_true], [str(p) for p in y_pred], pos_label="True"),
        "roc_auc": roc_auc,
        "roc_auc_unavailable_reason": roc_auc_reason,
        "confusion_matrix": cm,
        "labels": ["False", "True"],
    }


# ----------------------------------------------------------
# Report Generation
# ----------------------------------------------------------


def generate_report():
    """Generate the full evaluation report."""
    login = evaluate_login_model()
    session = evaluate_session_model()

    report = []
    report.append("=" * 70)
    report.append("AI MODEL EVALUATION REPORT")
    report.append("=" * 70)
    report.append("")

    # ── Login Model ──
    report.append("LOGIN MODEL")
    report.append("-" * 70)
    report.extend(_format_model_section(login))
    report.append("")

    # ── Session Model ──
    report.append("SESSION MODEL")
    report.append("-" * 70)
    report.extend(_format_model_section(session))
    report.append("")

    # ── Authentication Metrics ──
    report.append("AUTHENTICATION METRICS")
    report.append("-" * 70)
    auth_metrics = [
        ("False re-authentication rate", "UNAVAILABLE",
         "No independent ground truth exists. No evaluation utility or labelled scenario set defines legitimate vs suspicious events."),
        ("True re-authentication rate", "UNAVAILABLE",
         "No independent ground truth exists. Requires confirmed suspicious events independent of the system's own risk decisions."),
        ("Missed suspicious-event rate", "UNAVAILABLE",
         "No independent suspicious-event ground truth. The login dataset labels originate from RiskCalculator (rule-based), and session labels are synthetic. No five-event labelled scenario exists in the repository."),
        ("MFA trigger rate", "UNAVAILABLE",
         "No five-event MFA evaluation scenario exists. Denominator (5) is unjustified. MFA context is undefined in evaluation code."),
        ("Average re-authentication frequency", "UNAVAILABLE",
         "No traceable calculation. Requires session inventory and re-auth event log from evaluation infrastructure, which does not exist."),
    ]
    for metric, status, reason in auth_metrics:
        report.append(f"{metric}: {status}")
        report.append(f"  Reason: {reason}")
    report.append("")

    # ── Limitations ──
    report.append("LIMITATIONS")
    report.append("-" * 70)
    report.append("1. Synthetic Data")
    report.append("   Both datasets (login_attempts.csv and session_events.csv) are synthetic.")
    report.append("   They were generated by scripts in ai/scripts/ using fixed random seeds.")
    report.append("   They do not represent real-world user behaviour or attack patterns.")
    report.append("")
    report.append("2. Rule-Generated Login Labels")
    report.append("   The login dataset risk_level column is generated by RiskCalculator.calculate()")
    report.append("   (ai/src/services/risk_calculator.py) — a deterministic rule-based system.")
    report.append("   The ML model trains on these rule-based labels and is evaluated on the same distribution.")
    report.append("   Therefore, model performance measures agreement with the rule-based labelling process,")
    report.append("   NOT real-world attack-detection effectiveness.")
    report.append("")
    report.append("3. Synthetic Session Labels")
    report.append("   The session dataset unusual_activity labels are generated by random coin flip")
    report.append("   (ANOMALY_RATE=0.20 in generate_session_dataset.py). They do not represent")
    report.append("   confirmed attacks, security incidents, or empirical anomalies.")
    report.append("")
    report.append("4. No Independent Security Ground Truth")
    report.append("   No real-world security outcomes (confirmed attacks, breaches, audits) exist in the")
    report.append("   repository. The ai/data/real/ directory is empty. MongoDB export scripts require")
    report.append("   a live database connection. Until independent ground truth is collected,")
    report.append("   all security evaluation metrics remain UNAVAILABLE.")
    report.append("")
    report.append("5. In-Memory Session Architecture")
    report.append("   The backend session monitor uses in-memory storage (Map). Session-based metrics")
    report.append("   are limited by server uptime and cannot capture historical patterns.")
    report.append("")

    return "\n".join(report)


def _format_model_section(result):
    if "error" in result:
        return [f"ERROR: {result['error']}"]

    lines = []
    lines.append(f"Dataset: {result['dataset']}")
    lines.append(f"Classes: {', '.join(result['classes_present'])}")
    lines.append(f"Class distribution: {result['class_distribution']}")
    lines.append(f"Positive class: {result['positive_class']}")
    lines.append("")
    lines.append(f"Accuracy: {result['accuracy']:.4f} ({result['accuracy']:.2%})")
    lines.append(f"Precision: {result['precision']:.4f} ({result['precision']:.2%})" if result['precision'] is not None else "Precision: N/A (undefined)")
    lines.append(f"Recall: {result['recall']:.4f} ({result['recall']:.2%})" if result['recall'] is not None else "Recall: N/A (undefined)")
    lines.append(f"F1: {result['f1']:.4f}" if result['f1'] is not None else "F1: N/A (undefined)")
    lines.append(f"FPR: {result['fpr']:.4f} ({result['fpr']:.2%})" if result['fpr'] is not None else "FPR: N/A (undefined)")
    lines.append(f"FNR: {result['fnr']:.4f} ({result['fnr']:.2%})" if result['fnr'] is not None else "FNR: N/A (undefined)")
    roc_str = f"{result['roc_auc']:.6f}" if isinstance(result['roc_auc'], float) else str(result['roc_auc'])
    lines.append(f"ROC-AUC: {roc_str}")
    if result.get('roc_auc_unavailable_reason'):
        lines.append(f"  ROC-AUC note: {result['roc_auc_unavailable_reason']}")
    lines.append(f"Confusion Matrix: {result['confusion_matrix']}")
    lines.append(f"Labels: {result['labels']}")
    return lines


# ----------------------------------------------------------
# Test Mode (for evaluate.test.js)
# ----------------------------------------------------------


def run_tests():
    """Run focused tests on metric calculation functions. Returns dict."""
    results = {"passed": 0, "failed": 0, "tests": []}

    def check(name, actual, expected):
        if actual == expected:
            results["tests"].append({"name": name, "passed": True, "actual": actual})
            results["passed"] += 1
        else:
            results["tests"].append({"name": name, "passed": False, "actual": actual, "expected": expected})
            results["failed"] += 1

    def approx_check(name, actual, expected, tol=1e-6):
        if actual is None or expected is None:
            check(name, actual, expected)
        elif abs(float(actual) - float(expected)) <= tol:
            results["tests"].append({"name": name, "passed": True, "actual": actual})
            results["passed"] += 1
        else:
            results["tests"].append({"name": name, "passed": False, "actual": actual, "expected": expected})
            results["failed"] += 1

    # ── Test data ──
    y_binary = [0, 0, 1, 1]
    y_pred_perfect = [0, 0, 1, 1]
    y_pred_all_zero = [0, 0, 0, 0]
    y_pred_all_one = [1, 1, 1, 1]
    y_pred_partial = [0, 1, 1, 0]

    # ── Accuracy ──
    check("accuracy_perfect", calculate_accuracy(y_binary, y_pred_perfect), 1.0)
    check("accuracy_all_zero", calculate_accuracy(y_binary, y_pred_all_zero), 0.5)
    check("accuracy_partial", calculate_accuracy(y_binary, y_pred_partial), 0.5)

    # ── Precision ──
    approx_check("precision_perfect", calculate_precision(y_binary, y_pred_perfect, pos_label=1), 1.0)
    # Zero positive predictions: precision = 0/(0+0) = undefined → 0 via zero_division
    check("precision_zero_positives", calculate_precision(y_binary, y_pred_all_zero, pos_label=1), 0.0)
    approx_check("precision_partial", calculate_precision(y_binary, y_pred_partial, pos_label=1), 1.0 / 2)

    # ── Recall ──
    approx_check("recall_perfect", calculate_recall(y_binary, y_pred_perfect, pos_label=1), 1.0)
    approx_check("recall_partial", calculate_recall(y_binary, y_pred_partial, pos_label=1), 0.5)
    # All negatives in y_pred → FN=2, TP=0 → recall = 0/(0+2) = 0
    check("recall_no_positives", calculate_recall(y_binary, y_pred_all_zero, pos_label=1), 0.0)

    # ── F1 ──
    approx_check("f1_perfect", calculate_f1(y_binary, y_pred_perfect, pos_label=1), 1.0)
    check("f1_zero_positives", calculate_f1(y_binary, y_pred_all_zero, pos_label=1), 0.0)

    # ── Confusion Matrix ──
    cm = calculate_confusion_matrix(y_binary, y_pred_perfect, labels=[0, 1])
    check("confusion_matrix_perfect", cm, [[2, 0], [0, 2]])
    cm_partial = calculate_confusion_matrix(y_binary, y_pred_partial, labels=[0, 1])
    check("confusion_matrix_partial", cm_partial, [[1, 1], [1, 1]])

    # ── FPR ──
    approx_check("fpr_perfect", calculate_fpr(y_binary, y_pred_perfect, pos_label=1), 0.0)
    # y_pred_all_zero: FP=0, TN=2 → FPR = 0/(0+2) = 0
    check("fpr_no_false_positives", calculate_fpr(y_binary, y_pred_all_zero, pos_label=1), 0.0)
    # y_pred_all_one: FP=2, TN=0 → FPR = 2/(2+0) = 1.0
    approx_check("fpr_all_false_positives", calculate_fpr(y_binary, y_pred_all_one, pos_label=1), 1.0)

    # ── FNR ──
    approx_check("fnr_perfect", calculate_fnr(y_binary, y_pred_perfect, pos_label=1), 0.0)
    # y_pred_all_zero: FN=2, TP=0 → FNR = 2/(2+0) = 1.0
    approx_check("fnr_no_true_positives", calculate_fnr(y_binary, y_pred_all_zero, pos_label=1), 1.0)

    # ── ROC-AUC with valid binary classes ──
    approx_check("roc_auc_perfect", calculate_roc_auc(y_binary, [0.1, 0.2, 0.8, 0.9]), 1.0)
    approx_check("roc_auc_random", calculate_roc_auc(y_binary, [0.1, 0.4, 0.3, 0.2]), 0.5, tol=1e-6)

    # ── ROC-AUC with single class → None ──
    check("roc_auc_single_class", calculate_roc_auc([1, 1, 1, 1], [0.1, 0.2, 0.3, 0.4]), None)
    check("roc_auc_all_negative", calculate_roc_auc([0, 0, 0, 0], [0.1, 0.2, 0.3, 0.4]), None)

    # ── Missing class handling ──
    check("precision_missing_positive", calculate_precision([0, 0, 0, 0], [0, 0, 0, 0], pos_label=1), None)

    # ── Real model predictions (sanity checks) ──
    login_result = evaluate_login_model()
    if "error" not in login_result:
        check("login_accuracy_range", login_result["accuracy"] is not None and 0 <= login_result["accuracy"] <= 1, True)
        check("login_has_confusion_matrix", isinstance(login_result.get("confusion_matrix"), list), True)
        approx_check("login_fpr_valid", login_result["fpr"], login_result["fpr"], tol=1e-9)  # just check it's not None

    session_result = evaluate_session_model()
    if "error" not in session_result:
        check("session_accuracy_range", session_result["accuracy"] is not None and 0 <= session_result["accuracy"] <= 1, True)
        check("session_has_confusion_matrix", isinstance(session_result.get("confusion_matrix"), list), True)

    return results


# ----------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------


def main():
    if "--test" in sys.argv:
        results = run_tests()
        print(json.dumps(results, indent=2, default=str))
        return 0 if results["failed"] == 0 else 1

    report = generate_report()
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
