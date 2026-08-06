import pandas as pd

# Load the dataset
df = pd.read_csv("../datasets/security_events_cleaned.csv")

# Create the standard schema
normalized = df[
    [
        "event_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "event_type",
        "severity",
        "event_status"
    ]
]

# Rename event_status to status
normalized.rename(
    columns={"event_status": "status"},
    inplace=True
)

# Save the normalized dataset
normalized.to_csv(
    "../datasets/security_events_normalized.csv",
    index=False
)

print("Normalization completed successfully!")