import pandas as pd

# -------------------------------
# Load datasets
# -------------------------------

# Security events dataset
security_df = pd.read_csv("../data/incident_history_2000_rows_cleaned.csv")

# MITRE ATT&CK mapping dataset
mitre_df = pd.read_csv("../data/threat_intelligence_mitre_mapped.csv")

# -------------------------------
# Merge with MITRE ATT&CK mapping
# -------------------------------
# Replace 'event_type' with the actual common column if different.

mapped_df = security_df.merge(
    mitre_df,
    on="event_type",
    how="left"
)

# -------------------------------
# Keep required columns
# -------------------------------

columns = [
    "event_id",
    "timestamp",
    "event_type",
    "severity",
    "mitre_id",
    "technique_name",
    "tactic"
]

available_columns = [col for col in columns if col in mapped_df.columns]

mapped_df = mapped_df[available_columns]

# -------------------------------
# Save output
# -------------------------------

mapped_df.to_csv(
    "../data/security_events_mitre_mapped.csv",
    index=False
)

print("MITRE ATT&CK mapping completed successfully!")