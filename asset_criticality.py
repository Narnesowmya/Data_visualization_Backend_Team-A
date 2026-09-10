import pandas as pd
from pathlib import Path



BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "asset.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "asset_criticality.csv"
)


CRITICALITY_SCORES = {
    "Critical": 1.00,
    "High": 0.75,
    "Medium": 0.50,
    "Low": 0.25
}


print("=" * 70)
print("             MILESTONE 3 - TASK 2")
print("             ASSET CRITICALITY")
print("=" * 70)



print("\n[1] Loading Milestone 1 asset data...")

assets = pd.read_csv(INPUT_FILE)

print(
    "Asset dataset shape:",
    assets.shape
)


print("\nAvailable columns:")

print(
    assets.columns.tolist()
)


required_columns = [
    "asset_id",
    "asset_name",
    "asset_type",
    "owner",
    "department",
    "criticality",
    "operating_system"
]

missing_columns = [
    column
    for column in required_columns
    if column not in assets.columns
]

if missing_columns:

    raise ValueError(
        "Missing required asset columns: "
        + str(missing_columns)
    )

print(
    "\nAll required columns found."
)


print("\n[2] Checking criticality values...")

print(
    assets["criticality"]
    .value_counts(dropna=False)
)



assets["criticality"] = (
    assets["criticality"]
    .astype(str)
    .str.strip()
    .str.title()
)



valid_levels = set(
    CRITICALITY_SCORES.keys()
)

invalid_levels = set(
    assets["criticality"].dropna().unique()
) - valid_levels


if invalid_levels:

    raise ValueError(
        "Invalid criticality values found: "
        + str(invalid_levels)
    )


print(
    "\n[3] Creating criticality scores..."
)

assets["criticality_score"] = (
    assets["criticality"]
    .map(CRITICALITY_SCORES)
)



if assets["criticality_score"].isna().any():

    missing_scores = (
        assets["criticality_score"]
        .isna()
        .sum()
    )

    raise ValueError(
        f"{missing_scores} assets have no "
        "criticality score."
    )


final_columns = [
    "asset_id",
    "asset_name",
    "asset_type",
    "owner",
    "department",
    "criticality",
    "criticality_score",
    "operating_system"
]

result = assets[
    final_columns
].copy()


print("\n[4] Asset ID validation...")

print(
    "Total assets:",
    len(result)
)

print(
    "Unique asset IDs:",
    result["asset_id"].nunique()
)

print(
    "Duplicate asset IDs:",
    result["asset_id"].duplicated().sum()
)

print(
    "Missing asset IDs:",
    result["asset_id"].isna().sum()
)



print("\n" + "=" * 55)
print("CRITICALITY DISTRIBUTION")
print("=" * 55)

distribution = (
    result["criticality"]
    .value_counts()
)

for level in [
    "Critical",
    "High",
    "Medium",
    "Low"
]:

    print(
        f"{level:<10}: "
        f"{distribution.get(level, 0)}"
    )


print("\n" + "=" * 55)
print("CRITICALITY SCORE DISTRIBUTION")
print("=" * 55)

score_distribution = (
    result["criticality_score"]
    .value_counts()
    .sort_index(
        ascending=False
    )
)

for score, count in score_distribution.items():

    print(
        f"{score:.2f} : {count}"
    )



OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


result.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n" + "=" * 55)
print("SAMPLE RESULTS")
print("=" * 55)

print(
    result.head(10)
    .to_string(index=False)
)


print("\n" + "=" * 70)

print(
    "Task 2 output saved to:"
)

print(
    OUTPUT_FILE
)

print(
    "\nTASK 2 COMPLETED SUCCESSFULLY!"
)

print("=" * 70)