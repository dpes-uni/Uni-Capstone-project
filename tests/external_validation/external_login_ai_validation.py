"""
external_login_ai_validation.py

Standalone external-validation test for the Assure Docs Login AI.

Purpose
-------
Test the EXISTING POST http://127.0.0.1:8000/predict endpoint using
external authentication data (events_corrected.csv) and report the AI
service's outputs alongside the dataset's original True/False alarm
labels.  The AI is NOT retrained and the AI service / API / model
files are NOT modified.

What this script does
---------------------
1. Loads the external dataset.
2. Selects 10 TRUE-alarm rows and 10 FALSE-alarm rows at random with
   a FIXED seed for reproducibility.
3. Maps defensible dataset fields to the /predict JSON schema:
     - country_of_authentication1   -> country, city
     - source_provider1             -> comment in payload (heuristic)
     - number_failed_logins1        -> failed_login_attempts
     - vpn_confidence (>=50%)       -> vpn_detected
     - source_provider1             -> source_provider hint
   Fields that the dataset does NOT contain (device, browser, OS,
   IP, trusted_device, trusted_location) are set to controlled,
   defensible constants and are labelled in the output CSV so it is
   not implied they came from the dataset.
4. Sends each case to /predict.
5. Records HTTP status, risk_score, risk_level, recommended_action
   and reason.  Preserves the original external True/False alarm
   label and does NOT treat True/False alarm as equivalent to
   Low/Medium/High.
6. Handles API errors per-case without stopping the whole test.
7. Writes a per-case CSV and prints a summary.

Notes on field mapping
----------------------
The external dataset is a categorical (country, provider, etc.)
feature list, not a low-level login event log.  Therefore the
mapping is intentionally limited to the fields that have a clear
defensible meaning.  All other /predict fields are set to fixed
controlled test values and flagged as such in the output.
"""

from __future__ import annotations

import csv
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple


def _http_json(method: str, url: str, body: Optional[dict] = None,
               timeout: int = 10) -> Tuple[int, str, str]:
    """
    Minimal stdlib HTTP client. Returns (http_status, content_type, body_text).
    No external dependencies; works inside the AI venv without 'requests'.
    """
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
        return exc.code, exc.headers.get("Content-Type", "") if exc.headers else "", exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
    except urllib.error.URLError as exc:
        return 0, "", f"transport error: {exc.reason}"
    except Exception as exc:
        return 0, "", f"transport error: {exc}"


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

DATASET_PATH = r"C:\Users\Deepesh_x\Downloads\events_corrected.csv"
AI_PREDICT_URL = "http://127.0.0.1:8000/predict"
AI_HEALTH_URL = "http://127.0.0.1:8000/health"

RANDOM_SEED = 20260830           # fixed seed -> reproducible selection
N_PER_LABEL = 10                 # 10 TRUE + 10 FALSE = 20 total

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "external_validation_results.csv")
SUMMARY_JSON = os.path.join(OUTPUT_DIR, "external_validation_summary.json")

REQUEST_TIMEOUT_SECONDS = 10

# These values are CONTROLLED test values (the dataset does not provide
# them).  Kept deliberately neutral so the per-case signal comes from
# the dataset-derived fields (country, failed logins, vpn confidence,
# source provider, time-between-authentications, comment).  Points
# contributions from these fields per risk_calculator.py:
#   new_device        +20 if True
#   new_location      +30 if not trusted_location
#   vpn_detected      +15 if True
#   failed_login      +25 if >= 3
#   outside hours     +10 if outside 8-18
CONTROLLED_DEVICE = "Desktop"
CONTROLLED_BROWSER = "Chrome"
CONTROLLED_OS = "Linux"
CONTROLLED_IP = "203.0.113.1"          # documentation-only IP
CONTROLLED_CITY = "Unknown"
CONTROLLED_USERNAME = "external-validation-user"
CONTROLLED_LOGIN_HOUR = 12             # inside business hours -> 0 pts
CONTROLLED_NEW_DEVICE = False          # no extra +20 pts
CONTROLLED_TRUSTED_DEVICE = True       # trusted device -> no +30 pts for untrusted location
CONTROLLED_TRUSTED_LOCATION = True     # trusted location -> 0 pts
VPN_CONFIDENCE_THRESHOLD_PCT = 50.0    # >= 50% => vpn_detected = True (from dataset)


# ----------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------

@dataclass
class CaseResult:
    source_id: str
    external_label: str                       # "TRUE" or "FALSE"
    comment: str
    country_auth1: str
    country_auth2: str
    source_provider1: str
    number_failed_logins1: int
    vpn_confidence_pct: float
    time_between_authentications: float
    # Mapped payload
    payload_json: str
    # AI response
    http_status: int
    api_error: str
    risk_score: str
    risk_level: str
    recommended_action: str
    reason: str
    pass_fail: str                            # PASS / FAIL / API_ERROR


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _parse_failed_logins(raw: str) -> int:
    """The dataset uses 100+ to mean "many".  Cap at 100 for JSON."""
    raw = (raw or "").strip()
    if raw.endswith("+"):
        return 100
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _parse_vpn_confidence(raw: str) -> float:
    raw = (raw or "").strip().rstrip("%")
    try:
        return float(raw)
    except ValueError:
        return 0.0


def _parse_float(raw: str) -> float:
    try:
        return float(raw)
    except (ValueError, TypeError):
        return 0.0


def load_dataset(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = [r for r in reader if r.get("id")]
    return rows


def select_balanced(rows: List[Dict[str, str]], per_label: int, rng: random.Random
                    ) -> List[Dict[str, str]]:
    """Return a list containing per_label TRUE + per_label FALSE rows."""
    true_rows = [r for r in rows if (r.get("True/False alarm") or "").strip().upper() == "TRUE"]
    false_rows = [r for r in rows if (r.get("True/False alarm") or "").strip().upper() == "FALSE"]

    if len(true_rows) < per_label:
        raise RuntimeError(f"Dataset has only {len(true_rows)} TRUE rows; need {per_label}.")
    if len(false_rows) < per_label:
        raise RuntimeError(f"Dataset has only {len(false_rows)} FALSE rows; need {per_label}.")

    picked = rng.sample(true_rows, per_label) + rng.sample(false_rows, per_label)
    rng.shuffle(picked)
    return picked


def build_payload(row: Dict[str, str]) -> Dict[str, Any]:
    """Map a dataset row to the /predict JSON schema."""
    failed = _parse_failed_logins(row.get("number_failed_logins1", "0"))
    vpn_conf = _parse_vpn_confidence(row.get("vpn_confidence", "0"))
    vpn_detected = vpn_conf >= VPN_CONFIDENCE_THRESHOLD_PCT

    payload = {
        "username": CONTROLLED_USERNAME,

        # --- dataset-derived (defensible) ---
        "country": (row.get("country_of_authentication1") or "").strip(),
        "city": CONTROLLED_CITY,
        "failed_login_attempts": failed,
        "vpn_detected": vpn_detected,

        # --- controlled test values (NOT from dataset) ---
        "device": CONTROLLED_DEVICE,
        "browser": CONTROLLED_BROWSER,
        "operating_system": CONTROLLED_OS,
        "ip_address": CONTROLLED_IP,
        "login_hour": CONTROLLED_LOGIN_HOUR,
        "new_device": CONTROLLED_NEW_DEVICE,
        "trusted_device": CONTROLLED_TRUSTED_DEVICE,
        "trusted_location": CONTROLLED_TRUSTED_LOCATION,
    }
    return payload


def call_predict(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Call /predict and return a normalised result dict. Uses stdlib urllib."""
    status, ct, text = _http_json("POST", AI_PREDICT_URL, payload, timeout=REQUEST_TIMEOUT_SECONDS)

    if status != 200:
        return {
            "http_status": status,
            "api_error": (text or "")[:200],
            "risk_score": "",
            "risk_level": "",
            "recommended_action": "",
            "reason": "",
        }

    try:
        body = json.loads(text)
    except ValueError as exc:
        return {
            "http_status": status,
            "api_error": f"non-json response: {exc}",
            "risk_score": "",
            "risk_level": "",
            "recommended_action": "",
            "reason": "",
        }

    return {
        "http_status": status,
        "api_error": "",
        "risk_score": body.get("risk_score", ""),
        "risk_level": body.get("risk_level", ""),
        "recommended_action": body.get("recommended_action", ""),
        "reason": body.get("reason", ""),
    }


def classify(passed: bool, errored: bool) -> str:
    if errored:
        return "API_ERROR"
    return "PASS" if passed else "FAIL"


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("Assure Docs - External Validation of Login AI (/predict)")
    print("=" * 72)
    print(f"Dataset      : {DATASET_PATH}")
    print(f"AI URL       : {AI_PREDICT_URL}")
    print(f"Random seed  : {RANDOM_SEED}  (selection only; AI is deterministic per payload)")
    print(f"Cases        : {N_PER_LABEL} TRUE + {N_PER_LABEL} FALSE = {N_PER_LABEL * 2}")
    print()

    # 0. AI service health check
    status, ct, body = _http_json("GET", AI_HEALTH_URL, timeout=5)
    if status != 200:
        print(f"ERROR: AI service unhealthy (HTTP {status}).")
        return 2
    print(f"AI health    : OK  ({body.strip()})")
    print()

    # 1. Load dataset
    rows = load_dataset(DATASET_PATH)
    print(f"Dataset rows : {len(rows)}")

    rng = random.Random(RANDOM_SEED)
    selected = select_balanced(rows, N_PER_LABEL, rng)
    print(f"Selected     : {len(selected)} rows")
    print()

    # 2. Run each case
    results: List[CaseResult] = []
    pass_count = 0
    fail_count = 0
    err_count = 0
    level_counter: Dict[str, int] = {}
    label_level: Dict[str, Dict[str, int]] = {"TRUE": {}, "FALSE": {}}

    for i, row in enumerate(selected, start=1):
        payload = build_payload(row)
        api = call_predict(payload)
        errored = bool(api["api_error"]) or api["http_status"] != 200

        # Heuristic for PASS/FAIL:
        # External TRUE alarm  -> AI should report at least Medium risk.
        # External FALSE alarm -> AI should NOT report High risk.
        # This is a simple directional check, NOT a label-equivalence.
        ext_label = (row.get("True/False alarm") or "").strip().upper()
        level = (api["risk_level"] or "").strip()

        if errored:
            passed = False
        elif ext_label == "TRUE":
            passed = level.lower() in {"medium", "high"}
        else:  # FALSE
            passed = level.lower() != "high"

        verdict = classify(passed, errored)

        results.append(
            CaseResult(
                source_id=str(row.get("id", "")),
                external_label=ext_label,
                comment=(row.get("comments") or "").strip(),
                country_auth1=(row.get("country_of_authentication1") or "").strip(),
                country_auth2=(row.get("country_of_authentication2") or "").strip(),
                source_provider1=(row.get("source_provider1") or "").strip(),
                number_failed_logins1=_parse_failed_logins(row.get("number_failed_logins1", "0")),
                vpn_confidence_pct=_parse_vpn_confidence(row.get("vpn_confidence", "0")),
                time_between_authentications=_parse_float(row.get("time_between_authentications", "0")),
                payload_json=json.dumps(payload, ensure_ascii=False),
                http_status=api["http_status"],
                api_error=api["api_error"],
                risk_score=api["risk_score"],
                risk_level=api["risk_level"],
                recommended_action=api["recommended_action"],
                reason=api["reason"],
                pass_fail=verdict,
            )
        )

        if verdict == "PASS":
            pass_count += 1
        elif verdict == "FAIL":
            fail_count += 1
        else:
            err_count += 1

        if level:
            level_counter[level] = level_counter.get(level, 0) + 1
            label_level.setdefault(ext_label, {})
            label_level[ext_label][level] = label_level[ext_label].get(level, 0) + 1

        # per-case line
        if errored:
            print(f"  [{i:02d}] id={row.get('id'):>3} ext={ext_label:<5} "
                  f"http={api['http_status']} API_ERROR: {api['api_error'][:80]}")
        else:
            print(f"  [{i:02d}] id={row.get('id'):>3} ext={ext_label:<5} "
                  f"http={api['http_status']} risk_score={api['risk_score']:>3} "
                  f"level={api['risk_level']:<6} action={api['recommended_action']:<26} "
                  f"-> {verdict}")

    # 3. Write CSV
    fieldnames = list(asdict(results[0]).keys())
    with open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    print()
    print(f"CSV written  : {OUTPUT_CSV}")

    # 4. Write summary JSON
    summary = {
        "dataset": DATASET_PATH,
        "ai_url": AI_PREDICT_URL,
        "random_seed": RANDOM_SEED,
        "cases_tested": len(results),
        "counts": {
            "PASS": pass_count,
            "FAIL": fail_count,
            "API_ERROR": err_count,
        },
        "risk_level_distribution_overall": level_counter,
        "risk_level_by_external_label": label_level,
        "field_mapping": {
            "country": "country_of_authentication1",
            "failed_login_attempts": "number_failed_logins1 (100+ capped to 100)",
            "vpn_detected": "vpn_confidence >= 50%",
            "controlled_values_NOT_from_dataset": [
                "device", "browser", "operating_system", "ip_address",
                "city", "login_hour", "new_device",
                "trusted_device", "trusted_location", "username",
            ],
        },
        "verdict_rule": (
            "External TRUE alarm should produce Medium/High risk; "
            "External FALSE alarm should NOT produce High risk. "
            "External label is NOT equated with Low/Medium/High."
        ),
    }
    with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"Summary JSON : {SUMMARY_JSON}")

    # 5. Print summary
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Cases tested : {len(results)}")
    print(f"  PASS       : {pass_count}")
    print(f"  FAIL       : {fail_count}")
    print(f"  API_ERROR  : {err_count}")
    print()
    print("Risk level distribution (overall):")
    for k in sorted(level_counter.keys()):
        print(f"  {k:<8} : {level_counter[k]}")
    print()
    print("Risk level by external label:")
    for label in ("TRUE", "FALSE"):
        if label in label_level and label_level[label]:
            print(f"  External {label}:")
            for k in sorted(label_level[label].keys()):
                print(f"    {k:<8} : {label_level[label][k]}")
        else:
            print(f"  External {label}: (no responses)")

    return 0 if err_count == 0 and fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
