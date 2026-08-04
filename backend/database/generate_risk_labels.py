import os
import pandas as pd
from mongo_connection import db

# Locate the CSV file
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
csv_path = os.path.join(
    base_dir,
    "data",
    "feature_engineered_security_events_FIXED (3).csv"
)

# Read CSV
df = pd.read_csv(csv_path)

# Create risk_label from severity
df["risk_label"] = df["severity"].apply(lambda x: f"{x} Risk")

# Keep only required fields
risk_df = df[[
    "event_id",
    "severity",
    "risk_label"
]]

# MongoDB collection
collection = db["risk_labels"]

# Remove old data
collection.delete_many({})

# Insert new data
result = collection.insert_many(risk_df.to_dict("records"))

print(f"✅ Inserted {len(result.inserted_ids)} risk labels.")