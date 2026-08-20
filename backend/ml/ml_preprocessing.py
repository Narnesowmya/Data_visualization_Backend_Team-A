
import os
import json
import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

# 1. Feature configuration (final 15, per feature_selection.md)

# All numerical features -> median-imputed, then scaled
NUMERIC_FEATURES = [
    "severity_score",
    "failed_login_attempts",
    "failed_login_count",
    "cvss_score",
    "hour_of_day",
    "event_frequency",
    "number_of_alerts_per_user",
]

# Binary / flag features -> 0/1, no scaling
BINARY_FEATURES = [
    "malware_detected",    # raw: "Yes"/"No" -> normalized to 1/0
    "weekend_flag",        # already 0/1
    "malicious_ip_flag",   # already 0/1 (currently constant - see note above)
    "threat_feed_match",   # raw: "No Match"/other -> normalized to 0/1
]

# Categorical features -> label encoded (exactly as specified by teammate)
CATEGORICAL_FEATURES = [
    "event_type",
    "protocol",
    "os",
    "department",
]

EXCLUDED_COLUMNS = [
    "event_id", "timestamp", "username", "source_ip", "destination_ip",
    "device_name", "asset_name", "vulnerability_id", "attack_type",
    "threat_indicator", "severity", "source_country", "destination_country",
    "event_status", "cvss_score_source",
]

ARTIFACT_DIR = "artifacts"



# 2. Missing value handling (numerical -> median, categorical -> "Unknown")

def handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    for col in NUMERIC_FEATURES:
        if col in df.columns:
            df[col] = df[col].fillna(df[col].median())

    for col in CATEGORICAL_FEATURES:
        if col in df.columns:
            df[col] = df[col].fillna("Unknown")

    # Binary fields: normalize text -> 0/1, missing -> 0
    if "malware_detected" in df.columns:
        col = df["malware_detected"]
        if not pd.api.types.is_numeric_dtype(col):
            df["malware_detected"] = col.astype(str).str.strip().str.lower().map(
                {"yes": 1, "no": 0, "true": 1, "false": 0, "1": 1, "0": 0}
            )
        df["malware_detected"] = df["malware_detected"].fillna(0).astype(int)

    if "weekend_flag" in df.columns:
        df["weekend_flag"] = df["weekend_flag"].fillna(0).astype(int)

    if "malicious_ip_flag" in df.columns:
        df["malicious_ip_flag"] = df["malicious_ip_flag"].fillna(0).astype(int)

    if "threat_feed_match" in df.columns:
        col = df["threat_feed_match"]
        if not pd.api.types.is_numeric_dtype(col):
            df["threat_feed_match"] = col.astype(str).str.strip().str.lower().map(
                lambda v: 0 if v in ("no match", "nomatch", "none", "nan") else 1
            )
        df["threat_feed_match"] = df["threat_feed_match"].fillna(0).astype(int)

    return df



# 3. Categorical encoding (event_type, protocol, os, department only)

def encode_categoricals(df: pd.DataFrame, fit: bool = True, encoders: dict = None) -> tuple:
    df = df.copy()
    encoders = encoders or {}

    for col in CATEGORICAL_FEATURES:
        if col not in df.columns:
            continue
        if fit:
            le = LabelEncoder()
            df[col + "_enc"] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
        else:
            le = encoders[col]
            df[col + "_enc"] = df[col].astype(str).map(
                lambda v: le.transform([v])[0] if v in le.classes_ else -1
            )

    return df, encoders



# 4. Scaling (all numerical features)

def scale_numeric(df: pd.DataFrame, fit: bool = True, scaler: StandardScaler = None) -> tuple:
    df = df.copy()
    cols = [c for c in NUMERIC_FEATURES if c in df.columns]

    if fit:
        scaler = StandardScaler()
        df[cols] = scaler.fit_transform(df[cols])
    else:
        df[cols] = scaler.transform(df[cols])

    return df, scaler



# 5. Final feature matrix

def select_model_features(df: pd.DataFrame) -> tuple:
    encoded_cat = [c + "_enc" for c in CATEGORICAL_FEATURES if c + "_enc" in df.columns]
    cols = (
        [c for c in NUMERIC_FEATURES if c in df.columns]
        + [c for c in BINARY_FEATURES if c in df.columns]
        + encoded_cat
    )
    return df[cols], cols



# 6. Full pipeline

def preprocess(df: pd.DataFrame, fit: bool = True,
                encoders: dict = None, scaler: StandardScaler = None):
    df = handle_missing_values(df)
    df, encoders = encode_categoricals(df, fit=fit, encoders=encoders)
    df, scaler = scale_numeric(df, fit=fit, scaler=scaler)

    X, feature_columns = select_model_features(df)
    return X, feature_columns, encoders, scaler



# 7. Persistence (joblib, per teammate's suggestion - needed for Task-7 API)

def save_artifacts(encoders, scaler, feature_columns, X, out_dir=ARTIFACT_DIR):
    os.makedirs(out_dir, exist_ok=True)

    joblib.dump(encoders, os.path.join(out_dir, "encoders.pkl"))
    joblib.dump(scaler, os.path.join(out_dir, "scaler.pkl"))

    with open(os.path.join(out_dir, "feature_columns.json"), "w") as f:
        json.dump(feature_columns, f, indent=2)

    X.to_csv(os.path.join(out_dir, "processed_dataset.csv"), index=False)


def load_artifacts(out_dir=ARTIFACT_DIR):
    encoders = joblib.load(os.path.join(out_dir, "encoders.pkl"))
    scaler = joblib.load(os.path.join(out_dir, "scaler.pkl"))
    with open(os.path.join(out_dir, "feature_columns.json")) as f:
        feature_columns = json.load(f)
    return encoders, scaler, feature_columns



# 8. Demo / manual test

if __name__ == "__main__":
    df = pd.read_csv("feature_engineered_security_events_FIXED (3).csv")

    X, feature_columns, encoders, scaler = preprocess(df, fit=True)

    print("Model-ready feature matrix (X):", X.shape)
    print(X.head())
    print("\nFeature columns used (", len(feature_columns), "):", feature_columns)
    print("\nAny NaNs in X?", X.isna().sum().sum())

    save_artifacts(encoders, scaler, feature_columns, X)
    print(f"\nArtifacts + processed_dataset.csv saved to ./{ARTIFACT_DIR}/")
