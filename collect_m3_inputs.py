import pandas as pd
from pathlib import Path

# MILESTONE 3 - TASK 1


BASE_DIR = Path(__file__).resolve().parent.parent

# Milestone 2 output
M2_FILE = (
    BASE_DIR
    / "data"
    / "threat_classification_with_confidence.csv"
)

# Milestone 1 security events
M1_EVENTS_FILE = (
    BASE_DIR
    / "data"
    / "security_events.csv"
)

# Output
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_FILE = (
    OUTPUT_DIR
    / "m3_task1_inputs.csv"
)


print("=" * 70)
print("        MILESTONE 3 - TASK 1")
print("        COLLECT REQUIRED INPUTS")
print("=" * 70)


print("\n[1] Loading Milestone 2 output...")

m2 = pd.read_csv(M2_FILE)

print("M2 shape:", m2.shape)



print("\n[2] Loading Milestone 1 security events...")

m1 = pd.read_csv(M1_EVENTS_FILE)

print("M1 shape:", m1.shape)



print("\n[3] Validating M2 columns...")

required_m2 = [
    "event_id",
    "prediction",
    "anomaly_score"
]

for column in required_m2:

    if column not in m2.columns:

        raise ValueError(
            f"M2 column missing: {column}"
        )

if "threat_confidence_score" in m2.columns:

    m2 = m2.rename(
        columns={
            "threat_confidence_score":
            "confidence_score"
        }
    )

elif "confidence_score" not in m2.columns:

    raise ValueError(
        "M2 does not contain "
        "threat_confidence_score "
        "or confidence_score."
    )


print("\n[4] Validating M1 columns...")

required_m1 = [
    "event_id",
    "timestamp",
    "source_ip",
    "event_type",
    "severity",
    "asset_name"
]

for column in required_m1:

    if column not in m1.columns:

        raise ValueError(
            f"M1 column missing: {column}"
        )


print("All required columns found.")



m2_selected = m2[
    [
        "event_id",
        "prediction",
        "confidence_score",
        "anomaly_score"
    ]
].copy()



m1_selected = m1[
    [
        "event_id",
        "severity",
        "event_type",
        "asset_name",
        "source_ip",
        "timestamp"
    ]
].copy()



duplicate_events = (
    m1_selected["event_id"]
    .duplicated()
    .sum()
)

print(
    "\nDuplicate M1 event IDs:",
    duplicate_events
)

if duplicate_events > 0:

    m1_selected = (
        m1_selected
        .drop_duplicates(
            subset="event_id",
            keep="first"
        )
    )



print("\n[5] Merging M2 results with M1 context...")

result = pd.merge(
    m2_selected,
    m1_selected,
    on="event_id",
    how="left"
)



final_columns = [
    "event_id",
    "prediction",
    "confidence_score",
    "anomaly_score",
    "severity",
    "event_type",
    "asset_name",
    "source_ip",
    "timestamp"
]

result = result[
    final_columns
]


print("\n" + "=" * 55)
print("FINAL TASK 1 VALIDATION")
print("=" * 55)

print(
    "M2 records:",
    len(m2)
)

print(
    "M1 records:",
    len(m1)
)

print(
    "Final records:",
    len(result)
)

print(
    "Unique event IDs:",
    result["event_id"].nunique()
)

print(
    "Duplicate event IDs:",
    result["event_id"].duplicated().sum()
)



print("\nMissing values:")
print(
    result.isna().sum()
)



print("\nPrediction distribution:")

print(
    result["prediction"]
    .value_counts(dropna=False)
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

result.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\nFinal columns:")

for column in result.columns:

    print(" -", column)


print("\nSample output:")

print(
    result.head(10).to_string(
        index=False
    )
)


print("\nOutput saved to:")
print(OUTPUT_FILE)


print("\n" + "=" * 70)
print("        TASK 1 COMPLETED SUCCESSFULLY")
print("=" * 70)
