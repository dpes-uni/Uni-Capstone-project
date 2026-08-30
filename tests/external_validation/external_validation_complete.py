"""
external_validation_complete.py

Complete read-only external validation of the Assure Docs AI service
using ALL records from 5 external datasets.

Purpose
-------
Test the EXISTING POST endpoints:
  - http://127.0.0.1:8000/predict
  - http://127.0.0.1:8000/predict-session

against external datasets WITHOUT modifying AI/model/rules/API/backend.
No retraining, no config changes, no package installs.

Datasets:
1. events_corrected.csv          -> /predict (authentication events)
2. network_data_one_month.csv    -> contextual/unsupported (network traffic)
3. Cloud-Based_Services_logs.csv -> /predict-session (session activity)
4. Authentication_Logs_logs.csv  -> /predict (authentication attempts)
5. Big_company data1 .csv        -> mixed routing based on available fields

Outputs:
- Per-dataset CSV results
- Combined summary CSV
- Deterministic processing (no random sampling)
"""

from __future__ import annotations

import csv
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

DATASETS = {
    "events_corrected": Path(r"C:\Users\Deepesh_x\Downloads\events_corrected.csv"),
    "network_data_one_month": Path(r"C:\Users\Deepesh_x\Downloads\network_data_one_month.csv"),
    "cloud_based_services": Path(r"C:\Users\Deepesh_x\Downloads\Cloud-Based_Services_logs.csv"),
    "authentication_logs": Path(r"C:\Users\Deepesh_x\Downloads\Authentication_Logs_logs.csv"),
    "big_company": Path(r"C:\Users\Deepesh_x\Downloads\Big_company data1 .csv"),
}

AI_PREDICT_URL = "http://127.0.0.1:8000/predict"
AI_PREDICT_SESSION_URL = "http://127.0.0.1:8000/predict-session"
AI_HEALTH_URL = "http://127.0.0.1:8000/health"

REQUEST_TIMEOUT_SECONDS = 10

OUTPUT_DIR = Path(__file__).parent
OUTPUT_DIR.mkdir(exist_ok=True)

# Neutral controlled values for fields the API requires but datasets lack.
# These are CONSTANT per endpoint and clearly NOT from the datasets.
PREDICT_NEUTRALS = {
    "username": "external-validation-user",
    "device": "Desktop",
    "browser": "Chrome",
    "operating_system": "Linux",
    "ip_address": "203.0.113.1",
    "country": "Unknown",
    "city": "Unknown",
    "login_hour": 12,
    "new_device": False,
    "vpn_detected": False,
    "failed_login_attempts": 0,
    "trusted_device": True,
    "trusted_location": True,
}

SESSION_NEUTRALS = {
    "username": "external-validation-user",
    "user_role": "Student",
    "session_duration_minutes": 20,
    "documents_viewed": 3,
    "documents_downloaded": 1,
    "documents_uploaded": 1,
    "verification_actions": 2,
    "failed_actions": 0,
    "rapid_actions": False,
    "unusual_activity": False,
}

VPN_CONFIDENCE_THRESHOLD_PCT = 50.0


# ----------------------------------------------------------------------
# Minimal stdlib HTTP client
# ----------------------------------------------------------------------

def _http_json(method, url, body=None, timeout=REQUEST_TIMEOUT_SECONDS):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.headers.get("Content-Type", "") if exc.headers else ""), \
               (exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else "")
    except urllib.error.URLError as exc:
        return 0, "", f"transport error: {exc.reason}"
    except Exception as exc:
        return 0, "", f"transport error: {exc}"


# ----------------------------------------------------------------------
# Parsing helpers
# ----------------------------------------------------------------------

def _parse_int(raw, default=0):
    try:
        return int(float(str(raw).strip()))
    except (ValueError, TypeError, AttributeError):
        return default


def _parse_float(raw, default=0.0):
    try:
        return float(str(raw).strip())
    except (ValueError, TypeError, AttributeError):
        return default


def _parse_vpn_confidence(raw):
    try:
        return float(str(raw).strip().rstrip("%"))
    except (ValueError, TypeError, AttributeError):
        return 0.0


def _read_csv(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return [r for r in reader]


# ----------------------------------------------------------------------
# Result dataclass
# ----------------------------------------------------------------------

@dataclass
class ValidationRecord:
    dataset: str
    source_id: str
    original_fields_json: str
    mapped_fields_json: str
    unmapped_fields_json: str
    endpoint: str
    http_status: int
    api_error: str
    risk_score: str
    risk_level: str
    recommended_action: str
    reason: str


# ----------------------------------------------------------------------
# Dataset-specific mappers
# ----------------------------------------------------------------------

def map_events_corrected(row):
    failed = _parse_int(row.get("number_failed_logins1", "0"))
    vpn_conf = _parse_vpn_confidence(row.get("vpn_confidence", "0"))
    vpn_detected = vpn_conf >= VPN_CONFIDENCE_THRESHOLD_PCT
    payload = dict(PREDICT_NEUTRALS)
    payload["country"] = (row.get("country_of_authentication1") or "").strip()
    payload["failed_login_attempts"] = failed
    payload["vpn_detected"] = vpn_detected
    mapped = ["country", "failed_login_attempts", "vpn_detected"]
    unmapped = [
        "True/False alarm", "country_of_authentication2",
        "number_successful_logins1", "number_successful_logins2",
        "number_failed_logins2", "source_provider1", "source_provider2",
        "time_between_authentications", "comments"
    ]
    return payload, mapped, unmapped


def map_authentication_logs(row):
    username = (row.get("Username") or "").strip()
    if not username:
        return None, [], ["all - missing Username"]
    status = (row.get("Status") or "").strip()
    failed = 1 if status.lower() in {"failed", "failure", "error", "denied"} else 0
    payload = dict(PREDICT_NEUTRALS)
    payload["username"] = username
    payload["failed_login_attempts"] = failed
    mapped = ["username", "failed_login_attempts"]
    unmapped = ["Timestamp", "AuthenticationMethod", "Status"]
    return payload, mapped, unmapped


def map_big_company_login(row):
    user_id = (row.get("User ID") or "").strip()
    login_attempts = _parse_int(row.get("Login Attempts", "0"))
    email = (row.get("Email") or "").strip()
    if not user_id and not email:
        return None, [], ["all - no user identifier"]
    anomaly = (row.get("Anomaly Type") or "").strip().lower()
    vpn_detected = anomaly == "vpn"
    username = email if email else f"user_{user_id}"
    payload = dict(PREDICT_NEUTRALS)
    payload["username"] = username
    payload["failed_login_attempts"] = login_attempts
    payload["vpn_detected"] = vpn_detected
    mapped = ["username", "failed_login_attempts", "vpn_detected"]
    unmapped = [
        "Anomaly Type", "Historical Pattern Similarity", "Real-Time Behavior Score",
        "Mitigation Action", "Admin Notified", "Timestamp", "Login Time",
        "Login Frequency (30 days)", "Scroll Behavior", "Typical Actions",
        "Webcam Verification", "Update Type", "Status", "Affected Features",
        "User Name", "Phone Number"
    ]
    return payload, mapped, unmapped


def map_big_company_session(row):
    user_id = (row.get("User ID") or "").strip()
    email = (row.get("Email") or "").strip()
    if not user_id and not email:
        return None, [], ["all - no user identifier"]
    return None, [], ["all - no defensible session event mapping"]


def map_cloud_services(row):
    """
    Map Cloud-Based_Services_logs.csv to /predict-session.
    Uses EXACT match (case-insensitive) against a defensible set of
    operations. Substring matching is intentionally avoided so that
    operations like WRITE / CREATE / DELETE are NOT treated as
    document uploads. Ambiguous operations are marked unsupported.
    """
    username = (row.get("User") or "").strip()
    if not username:
        return None, [], ["all - missing User"]
    operation_raw = (row.get("Operation") or "").strip()
    operation = operation_raw.lower()

    if operation in {"read", "view"}:
        payload = dict(SESSION_NEUTRALS)
        payload["username"] = username
        payload["documents_viewed"] = 1
        mapped = ["username", "documents_viewed"]
        unmapped = ["Timestamp", "ServiceName", "Operation"]
        return payload, mapped, unmapped

    if operation == "download":
        payload = dict(SESSION_NEUTRALS)
        payload["username"] = username
        payload["documents_downloaded"] = 1
        mapped = ["username", "documents_downloaded"]
        unmapped = ["Timestamp", "ServiceName", "Operation"]
        return payload, mapped, unmapped

    if operation == "upload":
        payload = dict(SESSION_NEUTRALS)
        payload["username"] = username
        payload["documents_uploaded"] = 1
        mapped = ["username", "documents_uploaded"]
        unmapped = ["Timestamp", "ServiceName", "Operation"]
        return payload, mapped, unmapped

    if operation in {"verify", "auth"}:
        payload = dict(SESSION_NEUTRALS)
        payload["username"] = username
        payload["verification_actions"] = 1
        mapped = ["username", "verification_actions"]
        unmapped = ["Timestamp", "ServiceName", "Operation"]
        return payload, mapped, unmapped

    if operation in {"fail", "error", "deny"}:
        payload = dict(SESSION_NEUTRALS)
        payload["username"] = username
        payload["failed_actions"] = 1
        mapped = ["username", "failed_actions"]
        unmapped = ["Timestamp", "ServiceName", "Operation"]
        return payload, mapped, unmapped

    # write, create, delete, empty, or any other ambiguous operation
    return None, [], [
        f"Operation '{operation_raw}' is ambiguous - not defensibly mappable to session event counters"
    ]


def map_network_data_unsupported(row):
    return None, [], ["all - network traffic fields do not map to login/session schema"]


# ----------------------------------------------------------------------
# Process a dataset
# ----------------------------------------------------------------------

def process_dataset(name, path, predict_mapper, session_mapper=None):
    print("\n" + "=" * 72)
    print(f"Processing dataset: {name}")
    print("=" * 72)
    print(f"Path: {path}")
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        return [], {"total": 0, "predict": 0, "session": 0, "unsupported": 0, "errors": 0}
    rows = _read_csv(path)
    print(f"Total rows: {len(rows)}")
    records = []
    counters = {"total": 0, "predict": 0, "session": 0, "unsupported": 0, "errors": 0}
    for i, row in enumerate(rows):
        counters["total"] += 1
        source_id = str(row.get("id") or row.get("User ID") or row.get("Username") or
                        row.get("User") or row.get("Timestamp") or f"row_{i}")
        payload = None
        mapped = []
        unmapped = []
        endpoint = "unsupported"
        status = 0
        text = ""
        if predict_mapper:
            payload, mapped, unmapped = predict_mapper(row)
        if payload is not None:
            endpoint = "/predict"
            status, ct, text = _http_json("POST", AI_PREDICT_URL, payload)
            counters["predict"] += 1
        elif session_mapper:
            payload, mapped, unmapped = session_mapper(row)
            if payload is not None:
                endpoint = "/predict-session"
                status, ct, text = _http_json("POST", AI_PREDICT_SESSION_URL, payload)
                counters["session"] += 1
            else:
                endpoint = "unsupported"
                counters["unsupported"] += 1
        else:
            endpoint = "unsupported"
            counters["unsupported"] += 1
        api_error = ""
        risk_score = ""
        risk_level = ""
        recommended_action = ""
        reason = ""
        if endpoint in ("/predict", "/predict-session"):
            if status != 200:
                api_error = (text or "")[:500]
                counters["errors"] += 1
            else:
                try:
                    body = json.loads(text)
                    risk_score = str(body.get("risk_score", ""))
                    risk_level = body.get("risk_level", "")
                    recommended_action = body.get("recommended_action", "")
                    reason = body.get("reason", "")
                except (json.JSONDecodeError, ValueError) as exc:
                    api_error = f"non-json response: {exc}"
                    counters["errors"] += 1
        original_json = json.dumps(row, ensure_ascii=False)
        records.append(ValidationRecord(
            dataset=name,
            source_id=source_id,
            original_fields_json=original_json,
            mapped_fields_json=json.dumps({k: payload.get(k) for k in mapped}, ensure_ascii=False) if payload else "{}",
            unmapped_fields_json=json.dumps(unmapped, ensure_ascii=False),
            endpoint=endpoint,
            http_status=status,
            api_error=api_error,
            risk_score=risk_score,
            risk_level=risk_level,
            recommended_action=recommended_action,
            reason=reason,
        ))
        if (i + 1) % 50 == 0:
            print(f"  Processed {i+1}/{len(rows)}...")
    print(f"  Results: predict={counters['predict']}, session={counters['session']}, "
          f"unsupported={counters['unsupported']}, errors={counters['errors']}")
    return records, counters


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    print("=" * 72)
    print("Assure Docs AI - Complete External Validation (5 Datasets)")
    print("=" * 72)
    print("Checking AI service...")
    status, ct, body = _http_json("GET", AI_HEALTH_URL, timeout=5)
    if status != 200:
        print(f"ERROR: AI service unhealthy (HTTP {status}). Aborting.")
        return 2
    print(f"AI service: OK ({body.strip()})")
    all_records = []
    all_counters = {}
    recs, cnt = process_dataset("events_corrected", DATASETS["events_corrected"], map_events_corrected)
    all_records.extend(recs)
    all_counters["events_corrected"] = cnt
    recs, cnt = process_dataset("network_data_one_month", DATASETS["network_data_one_month"],
                                 predict_mapper=map_network_data_unsupported)
    all_records.extend(recs)
    all_counters["network_data_one_month"] = cnt
    recs, cnt = process_dataset("cloud_based_services", DATASETS["cloud_based_services"],
                                 predict_mapper=map_network_data_unsupported,
                                 session_mapper=map_cloud_services)
    all_records.extend(recs)
    all_counters["cloud_based_services"] = cnt
    recs, cnt = process_dataset("authentication_logs", DATASETS["authentication_logs"],
                                 predict_mapper=map_authentication_logs)
    all_records.extend(recs)
    all_counters["authentication_logs"] = cnt
    recs, cnt = process_dataset("big_company", DATASETS["big_company"],
                                 predict_mapper=map_big_company_login,
                                 session_mapper=map_big_company_session)
    all_records.extend(recs)
    all_counters["big_company"] = cnt
    fieldnames = ["dataset", "source_id", "original_fields_json", "mapped_fields_json",
                  "unmapped_fields_json", "endpoint", "http_status", "api_error",
                  "risk_score", "risk_level", "recommended_action", "reason"]
    for dataset_name, cnt in all_counters.items():
        dataset_records = [r for r in all_records if r.dataset == dataset_name]
        out_path = OUTPUT_DIR / f"{dataset_name}_validation_results.csv"
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in dataset_records:
                writer.writerow(asdict(r))
        print(f"  CSV written: {out_path}")
    combined_path = OUTPUT_DIR / "combined_validation_results.csv"
    with open(combined_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_records:
            writer.writerow(asdict(r))
    print(f"\nCombined CSV: {combined_path}")
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    for dataset_name, cnt in all_counters.items():
        dataset_records = [r for r in all_records if r.dataset == dataset_name]
        levels = {}
        for r in dataset_records:
            if r.risk_level:
                levels[r.risk_level] = levels.get(r.risk_level, 0) + 1
        print(f"\nDataset: {dataset_name}")
        print(f"  Total rows in CSV:          {cnt['total']}")
        print(f"  Rows sent to /predict:      {cnt['predict']}")
        print(f"  Rows sent to /predict-session: {cnt['session']}")
        print(f"  Unsupported/contextual:     {cnt['unsupported']}")
        print(f"  API errors:                 {cnt['errors']}")
        print(f"  Risk level distribution:")
        for level in sorted(levels.keys()):
            print(f"    {level:<8}: {levels[level]}")
    total_rows = sum(c['total'] for c in all_counters.values())
    total_predict = sum(c['predict'] for c in all_counters.values())
    total_session = sum(c['session'] for c in all_counters.values())
    total_unsupported = sum(c['unsupported'] for c in all_counters.values())
    total_errors = sum(c['errors'] for c in all_counters.values())
    print("\n" + "-" * 72)
    print("OVERALL TOTALS")
    print("-" * 72)
    print(f"  Rows in all datasets:          {total_rows}")
    print(f"  Rows sent to /predict:         {total_predict}")
    print(f"  Rows sent to /predict-session: {total_session}")
    print(f"  Unsupported/contextual:        {total_unsupported}")
    print(f"  API errors:                    {total_errors}")
    print(f"  Output directory:              {OUTPUT_DIR}")
    print("\n" + "-" * 72)
    print("MAPPING LIMITATIONS")
    print("-" * 72)
    print("""
1. events_corrected: Only country_auth1, failed_logins1, vpn_confidence mapped.
   country_auth2, time_between_authentications, comments, provider fields ignored.

2. network_data_one_month: No defensible mapping to /predict or /predict-session.
   All rows marked unsupported (contextual network telemetry only).

3. Cloud-Based_Services: Mapped to /predict-session using Operation heuristics.
   Counters inferred from single Operation string per row - coarse approximation.

4. Authentication_Logs: Only Username and Status->failed_login_attempts mapped.
   No country, VPN, device, or timing information available.

5. Big_company: Login rows mapped to /predict using Login Attempts, VPN from
   Anomaly Type, email/User ID as username. Session mapping NOT possible.

Neutral values used (NOT from any dataset):
  /predict: device, browser, OS, IP, city, login_hour, new_device, trusted_device, trusted_location
  /predict-session: user_role, session_duration_minutes, document/verification/failed counters, rapid/unusual flags
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
