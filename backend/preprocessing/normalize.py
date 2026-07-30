import pandas as pd

# Read dataset
df = pd.read_csv("../data/security_events_cleaned_FINAL (1).csv")

# Select required columns
normalized_df = df[
    [
        "event_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "event_type",
        "severity",
        "event_status"
    ]
].copy()

# Rename event_status to status
normalized_df.rename(
    columns={"event_status": "status"},
    inplace=True
)

# Save normalized dataset
normalized_df.to_csv(
    "../data/security_events_normalized.csv",
    index=False
)

print(normalized_df.head())