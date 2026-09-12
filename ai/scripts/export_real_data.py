"""
export_real_data.py

Exports real LoginActivity records from MongoDB into a CSV
with the same column schema used by the login model trainers.

Usage:
    python scripts/export_real_data.py

Requires MONGO_URI env var (defaults to mongodb://127.0.0.1:27017/assure_docs).
"""

import os
import re
import sys
from pathlib import Path

import pandas as pd
from pymongo import MongoClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "real"
OUTPUT_FILE = OUTPUT_DIR / "login_attempts_real.csv"
EXPORTED_IDS_FILE = OUTPUT_DIR / "exported_login_ids.txt"

# Target CSV columns (must match generate_login_dataset.py output)
COLUMNS = [
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
    "user_role",
    "organisation",
    "risk_score",
    "risk_level",
    "recommended_action",
    "reason",
]


# ----------------------------------------------------------
# User-Agent parsing (mirrors aiService.js extractDeviceInfo)
# ----------------------------------------------------------

def parse_user_agent(ua):
    device = "Unknown"
    browser = "Unknown"
    os_name = "Unknown"

    if not ua:
        return device, browser, os_name

    # Operating system
    if re.search(r"windows", ua, re.I):
        os_name = "Windows"
    elif re.search(r"macintosh|mac os x", ua, re.I):
        os_name = "MacOS"
    elif re.search(r"android", ua, re.I):
        os_name = "Android"
    elif re.search(r"iphone|ipad|ipod|ios", ua, re.I):
        os_name = "iOS"
    elif re.search(r"linux", ua, re.I):
        os_name = "Linux"

    # Browser
    if re.search(r"edg", ua, re.I):
        browser = "Edge"
    elif re.search(r"opr/", ua, re.I):
        browser = "Opera"
    elif re.search(r"chrome|crios", ua, re.I):
        browser = "Chrome"
    elif re.search(r"firefox|fxios", ua, re.I):
        browser = "Firefox"
    elif re.search(r"safari", ua, re.I):
        browser = "Safari"

    # Device type
    if re.search(r"tablet|ipad|playbook|silk", ua, re.I):
        device = "Tablet"
    elif re.search(r"mobile|android|iphone|ipod", ua, re.I):
        device = "Mobile"
    else:
        device = "Desktop"

    return device, browser, os_name


# ----------------------------------------------------------
# Risk level mapping
# ----------------------------------------------------------

def risk_level_label(score):
    if score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    return "Low"


def risk_action(level):
    return {
        "High": "Require Additional Verification",
        "Medium": "Require Email OTP",
        "Low": "Allow Login",
    }.get(level, "Allow Login")


# ----------------------------------------------------------
# Main export
# ----------------------------------------------------------

def load_exported_ids():
    if EXPORTED_IDS_FILE.exists():
        return set(EXPORTED_IDS_FILE.read_text().strip().split("\n"))
    return set()


def save_exported_id(doc_id):
    with open(EXPORTED_IDS_FILE, "a") as f:
        f.write(str(doc_id) + "\n")


def main():
    mongo_uri = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017/assure_docs")

    print("=" * 60)
    print(" Real Login Data Exporter")
    print("=" * 60)
    print(f"Mongo URI: {mongo_uri}")
    print(f"Output:   {OUTPUT_FILE}")

    client = MongoClient(mongo_uri)
    db = client.get_database()
    login_collection = db["loginactivities"]
    users_collection = db["users"]

    exported_ids = load_exported_ids()
    print(f"Already exported: {len(exported_ids)} records")

    # Fetch all login activities, sorted by creation date
    cursor = login_collection.find(
        {},
        sort=[("createdAt", 1)],
    )

    rows = []
    new_count = 0

    for doc in cursor:
        doc_id = str(doc["_id"])
        if doc_id in exported_ids:
            continue

        # Look up the user for email and role
        user_id = doc.get("user")
        user_doc = users_collection.find_one({"_id": user_id}) if user_id else None
        username = user_doc.get("email", "unknown") if user_doc else "unknown"
        user_role = user_doc.get("role", "student").capitalize() if user_doc else "Student"

        # Parse user-agent
        ua = doc.get("userAgent", "")
        device, browser, os_name = parse_user_agent(ua)

        # Derive features
        country = doc.get("country") or "Unknown"
        city = doc.get("city") or "Unknown"
        ip = doc.get("ip", "unknown")
        risk_score = doc.get("riskScore", 0)
        risk_level = risk_level_label(risk_score)
        reason = "; ".join(doc.get("riskReasons", [])) or "No reasons recorded"

        # Time-based feature
        created_at = doc.get("createdAt")
        login_hour = created_at.hour if created_at else 12

        # Feature flags from LoginActivity
        new_device = doc.get("isNewDevice", False)
        trusted_device = not new_device
        # Use isNewIp as proxy for trusted_location (not perfect but reasonable)
        trusted_location = not doc.get("isNewIp", False)

        # Login hour-based risk adjustment (outside business hours 8-18)
        if login_hour < 8 or login_hour >= 18:
            reason = "Login outside business hours" if reason == "No reasons recorded" else reason

        row = {
            "username": username,
            "device": device,
            "browser": browser,
            "operating_system": os_name,
            "ip_address": ip,
            "country": country,
            "city": city,
            "login_hour": login_hour,
            "failed_login_attempts": 0,  # Not stored per-record in LoginActivity
            "new_device": new_device,
            "vpn_detected": False,  # Not stored; could be added via ipService lookup
            "trusted_device": trusted_device,
            "trusted_location": trusted_location,
            "user_role": user_role,
            "organisation": "",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action": risk_action(risk_level),
            "reason": reason,
        }

        rows.append(row)
        exported_ids.add(doc_id)
        save_exported_id(doc_id)
        new_count += 1

    client.close()

    if not rows:
        print("\nNo new records to export.")
        return

    df = pd.DataFrame(rows, columns=COLUMNS)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Append to existing file or create new
    if OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0:
        df.to_csv(OUTPUT_FILE, mode="a", header=False, index=False)
    else:
        df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nExported {new_count} new records")
    print(f"Total rows in file: {len(pd.read_csv(OUTPUT_FILE))}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
