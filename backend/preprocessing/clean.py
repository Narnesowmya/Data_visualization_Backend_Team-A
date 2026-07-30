import pandas as pd

# --------------------------------
# Read the Dataset
# --------------------------------

df = pd.read_csv("../data/security_events_cleaned_FINAL (1).csv")

original_rows = len(df)

print("=" * 50)
print("SECURITY EVENTS DATA CLEANING")
print("=" * 50)

print(f"\nOriginal Dataset Shape : {df.shape}")

# --------------------------------
# Before Cleaning Report
# --------------------------------

print("\nBefore Cleaning Report")
print("-" * 30)

print("Missing Values:")
print(df.isnull().sum())

duplicate_count = df.duplicated().sum()
print(f"\nDuplicate Rows : {duplicate_count}")

invalid_timestamp_count = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
).isna().sum()

print(f"Invalid Timestamps : {invalid_timestamp_count}")

unknown_severity_count = (
    df["severity"]
    .isin(["Unknown", "unknown", "", "N/A", "NA"])
    .sum()
)

print(f"Unknown Severity : {unknown_severity_count}")

# --------------------------------
# Handle Missing / Null Values
# --------------------------------

# Remove rows where all values are null
df.dropna(how="all", inplace=True)

# Remove rows with missing event_id, timestamp or severity
df.dropna(
    subset=["event_id", "timestamp", "severity"],
    inplace=True
)

# --------------------------------
# Remove Duplicate Logs
# --------------------------------

df.drop_duplicates(inplace=True)

# --------------------------------
# Handle Invalid Timestamps
# --------------------------------

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

# Remove rows with invalid timestamps
df.dropna(subset=["timestamp"], inplace=True)

# --------------------------------
# Handle Unknown Severity
# --------------------------------

valid_severity = [
    "Low",
    "Medium",
    "High",
    "Critical"
]

df = df[df["severity"].isin(valid_severity)]

# --------------------------------
# Reset Index
# --------------------------------

df.reset_index(drop=True, inplace=True)

cleaned_rows = len(df)

# --------------------------------
# After Cleaning Report
# --------------------------------

print("\nAfter Cleaning Report")
print("-" * 30)

print(f"Cleaned Dataset Shape : {df.shape}")

print("\nMissing Values:")
print(df.isnull().sum())

print(f"\nDuplicate Rows : {df.duplicated().sum()}")

print("\nCleaning Summary")
print("-" * 30)
print(f"Rows Removed      : {original_rows - cleaned_rows}")
print(f"Final Row Count   : {cleaned_rows}")
print(f"Final Column Count: {df.shape[1]}")

# --------------------------------
# Save Cleaned Dataset
# --------------------------------

df.to_csv(
    "../data/security_events_cleaned.csv",
    index=False
)

print("\nCleaned dataset saved successfully!")

print("\nFirst 5 Rows:")
print(df.head())