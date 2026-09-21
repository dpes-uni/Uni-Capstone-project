"""
One-off driver: run external_validation_complete.py ONLY for
network_data_one_month.csv. Imports the existing module without modifying it.
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
    _http_json,
    map_network_data_unsupported,
    process_dataset,
)

# 1. /health check
status, _ct, body = _http_json("GET", AI_HEALTH_URL, timeout=5)
if status != 200:
    print(f"ERROR: AI service unhealthy (HTTP {status}). Aborting.")
    sys.exit(2)
print(f"AI health: OK ({body.strip()})")

# 2. Run network_data_one_month only
records, counters = process_dataset(
    "network_data_one_month",
    DATASETS["network_data_one_month"],
    predict_mapper=map_network_data_unsupported,
)

# 3. Write results CSV only if there are supported rows
fieldnames = [
    "dataset", "source_id", "original_fields_json", "mapped_fields_json",
    "unmapped_fields_json", "endpoint", "http_status", "api_error",
    "risk_score", "risk_level", "recommended_action", "reason",
]
out_path = OUTPUT_DIR / "network_data_one_month_validation_results.csv"
with open(out_path, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in records:
        writer.writerow(asdict(r))

# 4. Report
print()
print("=" * 60)
print("REPORT (network_data_one_month only)")
print("=" * 60)
print(f"total rows              : {counters['total']}")
print(f"supported rows          : {counters['predict'] + counters['session']}")
print(f"contextual/unsupported  : {counters['unsupported']}")
print(f"API requests made       : {counters['predict'] + counters['session']}")
print(f"API errors             : {counters['errors']}")
print(f"output CSV path         : {out_path}")
