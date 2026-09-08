import csv
from threat_predictions import save_prediction, get_predictions

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = BASE_DIR / "data" / "threat_classification_with_confidence.csv"

# Get existing records from MongoDB
existing_predictions = get_predictions()

existing_keys = {
    (
        row.get("event_id"),
        row.get("prediction"),
        row.get("threat_type"),
        row.get("confidence_score"),
        row.get("anomaly_score"),
        row.get("severity"),
        row.get("model_version")
    )
    for row in existing_predictions
}

inserted = 0
skipped = 0

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        prediction = {
            "event_id": row["event_id"],
            "prediction": row["prediction"],
            "threat_type": row["threat_type"],
            "confidence_score": float(row["threat_confidence_score"]),
            "anomaly_score": float(row["anomaly_score"]),
            "severity": row["severity"],
            "model_version": "IF_v1"
        }

        key = (
            prediction["event_id"],
            prediction["prediction"],
            prediction["threat_type"],
            prediction["confidence_score"],
            prediction["anomaly_score"],
            prediction["severity"],
            prediction["model_version"]
        )

        if key in existing_keys:
            skipped += 1
            continue

        save_prediction(prediction)

        existing_keys.add(key)
        inserted += 1

        if inserted % 100 == 0:
            print(f"Inserted: {inserted}")

print("\nImport completed!")
print(f"New records inserted: {inserted}")
print(f"Existing records skipped: {skipped}")