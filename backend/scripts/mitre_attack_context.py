import pandas as pd
from pathlib import Path


# ============================================================
# Task 4: MITRE ATT&CK Threat Context
# ============================================================
#
# Input:
#   data/mitre_attack_mapping_cleaned.csv
#
# Output:
#   data/mitre_attack_context.csv
#
# Purpose:
#   Reuse the existing MITRE ATT&CK mapping dataset as
#   threat context for Milestone 3.
#
# IMPORTANT:
#   This task does NOT:
#       - create MITRE mappings
#       - invent event IDs
#       - calculate risk scores
#       - calculate MITRE confidence
#       - assign MITRE weights
#       - create event-level records
#
# The output is intentionally a reusable lookup/context table.
#
# Mapping:
#
#   mapped_event_type
#          ↓
#      mitre_id
#          ↓
#   technique_name
#          ↓
#        tactic
#
# Downstream integration:
#
#   M2 event_type
#          ↓
#   mapped_event_type
#          ↓
#   MITRE context
#
# The Risk Engine / enrichment layer can later attach the
# appropriate MITRE information to an event.
#
# ============================================================


# ------------------------------------------------------------
# 1. Define paths
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "mitre_attack_mapping_cleaned.csv"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "mitre_attack_context.csv"
)


# ------------------------------------------------------------
# 2. Load existing MITRE dataset
# ------------------------------------------------------------

df = pd.read_csv(INPUT_FILE)


# ------------------------------------------------------------
# 3. Required columns
# ------------------------------------------------------------

required_columns = [
    "mapped_event_type",
    "mitre_id",
    "technique_name",
    "tactic",
]


# ------------------------------------------------------------
# 4. Validate required columns
# ------------------------------------------------------------

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required MITRE columns: "
        f"{missing_columns}"
    )


# ------------------------------------------------------------
# 5. Validate missing values
# ------------------------------------------------------------

missing_values = (
    df[required_columns]
    .isna()
    .sum()
)

if missing_values.any():

    columns_with_missing = (
        missing_values[
            missing_values > 0
        ]
        .to_dict()
    )

    raise ValueError(
        "MITRE mapping contains missing values: "
        f"{columns_with_missing}"
    )


# ------------------------------------------------------------
# 6. Clean whitespace
# ------------------------------------------------------------
#
# This does NOT change the meaning of the existing data.
# It only prevents accidental join failures such as:
#
# "Brute Force"
# vs
# "Brute Force "
# ------------------------------------------------------------

for column in required_columns:

    df[column] = (
        df[column]
        .astype(str)
        .str.strip()
    )


# ------------------------------------------------------------
# 7. Validate empty values after stripping
# ------------------------------------------------------------

empty_values = {}

for column in required_columns:

    empty_count = (
        df[column]
        .eq("")
        .sum()
    )

    if empty_count > 0:
        empty_values[column] = int(empty_count)


if empty_values:

    raise ValueError(
        "MITRE mapping contains empty values: "
        f"{empty_values}"
    )


# ------------------------------------------------------------
# 8. Validate duplicate complete mappings
# ------------------------------------------------------------
#
# Identical complete rows are not useful because they would
# unnecessarily duplicate the lookup result.
# ------------------------------------------------------------

duplicate_count = (
    df.duplicated(
        subset=required_columns
    ).sum()
)


if duplicate_count > 0:

    raise ValueError(
        f"Found {duplicate_count} duplicate "
        "MITRE mapping records."
    )


# ------------------------------------------------------------
# 9. Preserve existing MITRE mappings
# ------------------------------------------------------------
#
# We intentionally DO NOT manually map:
#
# Brute Force -> T1110
#
# or any other event type.
#
# The existing dataset is the source of truth.
#
# An event type can have multiple MITRE techniques.
# Therefore all existing mappings are preserved.
# ------------------------------------------------------------

output_df = df[
    required_columns
].copy()


# ------------------------------------------------------------
# 10. Validate record count
# ------------------------------------------------------------

if len(output_df) != len(df):

    raise ValueError(
        "Task 4 changed the number of MITRE records."
    )


# ------------------------------------------------------------
# 11. Validate unique MITRE IDs / techniques
# ------------------------------------------------------------

if output_df["mitre_id"].eq("").any():

    raise ValueError(
        "MITRE ID contains empty values."
    )

if output_df["technique_name"].eq("").any():

    raise ValueError(
        "MITRE technique name contains empty values."
    )

if output_df["tactic"].eq("").any():

    raise ValueError(
        "MITRE tactic contains empty values."
    )


# ------------------------------------------------------------
# 12. Save Task 4 output
# ------------------------------------------------------------

output_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ------------------------------------------------------------
# 13. Summary
# ------------------------------------------------------------

print(
    "Task 4 completed successfully."
)

print(
    f"Input MITRE records: {len(df)}"
)

print(
    f"Output MITRE records: {len(output_df)}"
)

print(
    f"Output file: {OUTPUT_FILE}"
)


# ------------------------------------------------------------
# 14. Output columns
# ------------------------------------------------------------

print(
    "\nOutput columns:"
)

print(
    output_df.columns.tolist()
)


# ------------------------------------------------------------
# 15. Unique values
# ------------------------------------------------------------

print(
    "\nUnique event types:"
)

print(
    output_df[
        "mapped_event_type"
    ].nunique()
)


print(
    "\nUnique MITRE IDs:"
)

print(
    output_df[
        "mitre_id"
    ].nunique()
)


print(
    "\nUnique techniques:"
)

print(
    output_df[
        "technique_name"
    ].nunique()
)


print(
    "\nUnique tactics:"
)

print(
    output_df[
        "tactic"
    ].nunique()
)


# ------------------------------------------------------------
# 16. Tactic distribution
# ------------------------------------------------------------

print(
    "\nTactic distribution:"
)

print(
    output_df[
        "tactic"
    ]
    .value_counts()
    .to_string()
)


# ------------------------------------------------------------
# 17. Event type distribution
# ------------------------------------------------------------

print(
    "\nEvent type distribution:"
)

print(
    output_df[
        "mapped_event_type"
    ]
    .value_counts()
    .to_string()
)


# ------------------------------------------------------------
# 18. First 10 records
# ------------------------------------------------------------

print(
    "\nFirst 10 records:"
)

print(
    output_df
    .head(10)
    .to_string(index=False)
)


# ------------------------------------------------------------
# 19. Integration note
# ------------------------------------------------------------

print(
    "\nTask 4 integration:"
)

print(
    "MITRE data is retained as reusable threat context."
)

print(
    "No event IDs are invented."
)

print(
    "No risk score is calculated."
)

print(
    "No additional MITRE risk weight is applied."
)

print(
    "Downstream enrichment can map M2 event_type "
    "to mapped_event_type and attach MITRE context."
)