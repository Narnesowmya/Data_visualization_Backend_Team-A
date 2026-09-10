import os
import json
import pandas as pd
import joblib


# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ARTIFACT_DIR = os.path.join(
    BASE_DIR,
    "artifacts"
)

DATA_FILE = os.path.join(
    ARTIFACT_DIR,
    "processed_dataset.csv"
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "model.pkl"
)

PREDICTION_FILE = os.path.join(
    BASE_DIR,
    "anomaly_predictions.csv"
)


# =========================================================
# LOAD PROCESSED DATA
# =========================================================

print("\nLoading processed dataset...")

data = pd.read_csv(DATA_FILE)

print("Dataset loaded successfully!")
print("Dataset shape:", data.shape)


# =========================================================
# LOAD FEATURE COLUMNS
# =========================================================

FEATURE_FILE = os.path.join(
    ARTIFACT_DIR,
    "feature_columns.json"
)

with open(FEATURE_FILE, "r") as file:
    features = json.load(file)

print("\nFeatures used by model:")
for feature in features:
    print("-", feature)


# =========================================================
# CHECK FEATURES
# =========================================================

missing_features = [
    feature
    for feature in features
    if feature not in data.columns
]

if missing_features:
    raise ValueError(
        f"Missing required model features: {missing_features}"
    )


# =========================================================
# SELECT ONLY MODEL FEATURES
# =========================================================

# =========================================================
# PREPARE FEATURES FOR OFFICIAL TASK-3 MODEL
# =========================================================

# The official Task-3 model expects severity_score.
# Some newer preprocessing files contain severity_enc instead.

if "severity_score" not in data.columns:

    from sklearn.preprocessing import StandardScaler

    if "severity" in data.columns:
        severity_mapping = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }

        raw_sev = (
            data["severity"]
            .astype(str)
            .str.strip()
            .str.title()
            .map(severity_mapping)
        )
        data["severity_score"] = StandardScaler().fit_transform(raw_sev.values.reshape(-1, 1)).flatten()

    elif "severity_enc" in data.columns:
        raw_sev = data["severity_enc"] + (1 if data["severity_enc"].min() == 0 else 0)
        data["severity_score"] = StandardScaler().fit_transform(raw_sev.values.reshape(-1, 1)).flatten()

    else:
        raise ValueError(
            "Neither severity_score nor severity/severity_enc "
            "is available."
        )


# Official Task-3 model feature order
features = [
    "failed_login_attempts",
    "cvss_score",
    "malware_detected",
    "severity_score",
    "event_type_enc",
    "protocol_enc",
    "os_enc",
    "department_enc"
]

missing_features = [
    feature for feature in features
    if feature not in data.columns
]

if missing_features:
    raise ValueError(
        f"Missing required Task-3 model features: {missing_features}"
    )

X = data[features].copy()

X = X.fillna(0)

print("\nFeature matrix shape:", X.shape)
print("\nFinal features passed to official Task-3 model:")

for feature in features:
    print("-", feature)

X = X.fillna(0)

print("\nFeature matrix shape:", X.shape)


# =========================================================
# LOAD OFFICIAL TASK-3 MODEL
# =========================================================

print("\nLoading official Task-3 model...")

if not os.path.exists(MODEL_FILE):
    raise FileNotFoundError(
        f"Official Task-3 model not found: {MODEL_FILE}"
    )

isolation_forest = joblib.load(MODEL_FILE)

print("Official Task-3 model loaded successfully!")

print(
    "Model type:",
    type(isolation_forest).__name__
)

print(
    "Model contamination:",
    isolation_forest.contamination
)


# =========================================================
# VERIFY OFFICIAL MODEL
# =========================================================

if isolation_forest.contamination != 0.05:
    raise ValueError(
        "\nIncorrect model detected!\n"
        "The official Task-3 model must use "
        "contamination=0.05."
    )

print(
    "Model verification passed: "
    "contamination=0.05"
)


# =========================================================
# GENERATE PREDICTIONS
# =========================================================

print("\nGenerating anomaly predictions...")

predictions = isolation_forest.predict(X)

anomaly_scores = isolation_forest.decision_function(X)


# =========================================================
# CONVERT PREDICTIONS TO LABELS
# =========================================================

labels = [
    "Normal" if prediction == 1 else "Suspicious"
    for prediction in predictions
]


# =========================================================
# SAVE PREDICTIONS
# =========================================================

results = data[features].copy()

results["prediction"] = labels

results["anomaly_score"] = anomaly_scores

results.to_csv(
    PREDICTION_FILE,
    index=False
)


# =========================================================
# SUMMARY
# =========================================================

print("\n========================================")
print("Task-3 official model inference completed")
print("========================================")

print("\nPrediction distribution:")

print(
    results["prediction"].value_counts()
)


print("\nExpected distribution for the approved model:")
print("Normal: approximately 9500")
print("Suspicious: approximately 500")


print("\nModel used:")
print(MODEL_FILE)


print("\nPredictions saved to:")
print(PREDICTION_FILE)


print("\nNumber of records:", len(results))


print("\nFeatures used:")

for feature in features:
    print("-", feature)


print("\nNo model retraining was performed.")
print("The official Task-3 model was used unchanged.")