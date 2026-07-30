import pandas as pd

# --------------------------------
# Read the Dataset
# --------------------------------

df = pd.read_csv("../data/security_events_cleaned.csv")

print("=" * 50)
print("STANDARDIZE SEVERITY LEVELS")
print("=" * 50)

print("\nSeverity Values Before Standardization")
print("-" * 40)
print(df["severity"].value_counts())

# --------------------------------
# Standardize Severity Levels
# --------------------------------

df["severity"] = (
    df["severity"]
    .str.strip()
    .str.lower()
)

severity_mapping = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low"
}

df["severity"] = df["severity"].replace(severity_mapping)

print("\nSeverity Values After Standardization")
print("-" * 40)
print(df["severity"].value_counts())

# --------------------------------
# Save Dataset
# --------------------------------

df.to_csv(
    "../data/security_events_standardized.csv",
    index=False
)

print("\nSeverity standardization completed successfully!")