import pandas as pd

# --------------------------------
# Read Datasets
# --------------------------------

security_df = pd.read_csv("../data/security_events_standardized.csv")
threat_df = pd.read_csv("../data/threat_intelligence_cleaned.csv")

print("=" * 60)
print("THREAT INTELLIGENCE ENRICHMENT")
print("=" * 60)

print("\nSecurity Events Dataset Shape :", security_df.shape)
print("Threat Intelligence Dataset Shape :", threat_df.shape)

# --------------------------------
# Brute Force Attack Detection
# --------------------------------

security_df["attack_type"] = security_df["failed_login_attempts"].apply(
    lambda x: "Possible Brute Force Attack"
    if x >= 10 else "Normal Activity"
)

# --------------------------------
# Extract Malicious IP Addresses
# --------------------------------

malicious_ips = set(

    threat_df.loc[
        threat_df["indicator_type"] == "IP Address",
        "indicator_value"

    ].astype(str).str.strip()

)

print("\nNumber of Malicious IPs :", len(malicious_ips))

# --------------------------------
# Threat Indicator
# --------------------------------

# --------------------------------
# Threat Indicator
# --------------------------------

security_df["threat_indicator"] = (
    security_df["source_ip"]
    .astype(str)
    .str.strip()
    .isin(malicious_ips)
    |
    security_df["destination_ip"]
    .astype(str)
    .str.strip()
    .isin(malicious_ips)
)

# --------------------------------
# Summary Report
# --------------------------------

print("\nEnrichment Summary")
print("-" * 30)

print(
    "Possible Brute Force Attacks :",
    (security_df["attack_type"] == "Possible Brute Force Attack").sum()
)

print(
    "Threat Indicator = True :",
    security_df["threat_indicator"].sum()
)

# --------------------------------
# Save Enriched Dataset
# --------------------------------

security_df.to_csv(
    "../data/security_events_enriched.csv",
    index=False
)

print("\nEnriched dataset saved successfully!")

print("\nFirst 5 Rows")
print(security_df.head())