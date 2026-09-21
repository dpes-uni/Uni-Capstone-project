"""
export_session_data.py

Exports real SessionEvent records from MongoDB into a CSV
with the same column schema used by the session model trainer.

Usage:
    python scripts/export_session_data.py

Requires MONGO_URI env var (defaults to mongodb://127.0.0.1:27017/assure_docs).
"""

import os
import sys
from pathlib import Path

import pandas as pd
from pymongo import MongoClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "real"
OUTPUT_FILE = OUTPUT_DIR / "session_events_real.csv"
EXPORTED_IDS_FILE = OUTPUT_DIR / "exported_session_ids.txt"

# Target CSV columns (must match generate_session_dataset.py output)
COLUMNS = [
    "session_duration_minutes",
    "documents_viewed",
    "documents_downloaded",
    "documents_uploaded",
    "verification_actions",
    "failed_actions",
    "rapid_actions",
    "username",
    "user_role",
    "unusual_activity",
]


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
    print(" Real Session Data Exporter")
    print("=" * 60)
    print(f"Mongo URI: {mongo_uri}")
    print(f"Output:   {OUTPUT_FILE}")

    client = MongoClient(mongo_uri)
    db = client.get_database()
    session_collection = db["sessionevents"]
    users_collection = db["users"]

    exported_ids = load_exported_ids()
    print(f"Already exported: {len(exported_ids)} records")

    cursor = session_collection.find(
        {},
        sort=[("createdAt", 1)],
    )

    rows = []
    new_count = 0

    for doc in cursor:
        doc_id = str(doc["_id"])
        if doc_id in exported_ids:
            continue

        # Look up user for email and role
        user_id = doc.get("user")
        user_doc = users_collection.find_one({"_id": user_id}) if user_id else None
        username = user_doc.get("email", "unknown") if user_doc else "unknown"
        user_role = doc.get("userRole") or (user_doc.get("role", "student").capitalize() if user_doc else "Student")

        row = {
            "session_duration_minutes": doc.get("sessionDurationMinutes", 0),
            "documents_viewed": doc.get("documentsViewed", 0),
            "documents_downloaded": doc.get("documentsDownloaded", 0),
            "documents_uploaded": doc.get("documentsUploaded", 0),
            "verification_actions": doc.get("verificationActions", 0),
            "failed_actions": doc.get("failedActions", 0),
            "rapid_actions": doc.get("rapidActions", False),
            "username": username,
            "user_role": user_role,
            "unusual_activity": doc.get("unusualActivity", False),
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

    if OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0:
        df.to_csv(OUTPUT_FILE, mode="a", header=False, index=False)
    else:
        df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nExported {new_count} new records")
    print(f"Total rows in file: {len(pd.read_csv(OUTPUT_FILE))}")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
