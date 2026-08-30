"""
One-off driver: run external_validation_complete.py ONLY for
events_corrected.csv. Imports the existing module without modifying it.
"""
import csv
import sys
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from external_validation_complete import (
    AI_HEALTH_URL,
    DATASETS,
    OUTPUT_DIR,
    ValidationRecord,
    _http_json,
    map_events_corrected,
    process_dataset,
)

# 1. /health check
status, _ct, body = _http_json("GET", AI_HEALTH_URL, timeout=5)
if status != 200:
    print(f"ERROR: AI service unhealthy (HTTP {status}). Aborting.")
    sys.exit(2)
print(f"AI health: OK ({body.strip()})")

# 2. Run events_corrected only
records, counters = process_dataset(
    "events_corrected",
    DATASETS["events_corrected"],
    map_events_corrected,
)

# 3. Write NEW per-dataset CSV (does NOT overwrite the 20-case results)
fieldnames = [
    "dataset", "source_id", "original_fields_json", "mapped_fields_json",
    "unmapped_fields_json", "endpoint", "http_status", "api_error",
    "risk_score", "risk_level", "recommended_action", "reason",
]
out_path = OUTPUT_DIR / "events_corrected_validation_results.csv"
with open(out_path, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in records:
        writer.writerow(asdict(r))

# 4. Aggregate risk levels
levels = {"Low": 0, "Medium": 0, "High": 0}
for r in records:
    if r.risk_level in levels:
        levels[r.risk_level] += 1

# 5. Report
print()
print("=" * 60)
print("REPORT (events_corrected only)")
print("=" * 60)
print(f"total rows              : {counters['total']}")
print(f"rows sent to /predict   : {counters['predict']}")
print(f"unsupported rows        : {counters['unsupported']}")
print(f"API errors              : {counters['errors']}")
print(f"Low                     : {levels['Low']}")
print(f"Medium                  : {levels['Medium']}")
print(f"High                    : {levels['High']}")
print(f"output CSV path         : {out_path}")
