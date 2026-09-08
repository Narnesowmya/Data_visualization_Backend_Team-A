import os
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from joblib import dump


# --------------------------------------------------
# 1. File paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "processed_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "model.pkl")
PREDICTIONS_PATH = os.path.join(
    BASE_DIR, "data", "anomaly_predictions.csv"
)


# --------------------------------------------------
# 2. Load processed dataset
# --------------------------------------------------

data = pd.read_csv(DATA_PATH)

print("Dataset loaded successfully!")
print("Dataset shape:", data.shape)

print("\nAvailable columns:")
print(data.columns.tolist())


# --------------------------------------------------
# 3. Select ML features
# --------------------------------------------------


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

# Check that all required features exist
missing_features = [
    feature for feature in features
    if feature not in data.columns
]

if missing_features:
    raise ValueError(
        f"Missing required features: {missing_features}"
    )

X = data[features].copy()

print("\nSelected features:")
print(features)

print("\nFeature matrix shape:", X.shape)


# --------------------------------------------------
# 4. Isolation Forest
# --------------------------------------------------

isolation_forest = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

isolation_predictions = isolation_forest.fit_predict(X)

# Convert:
#  1  -> Normal
# -1  -> Suspicious

isolation_labels = [
    "Normal" if prediction == 1 else "Suspicious"
    for prediction in isolation_predictions
]

# Anomaly score
anomaly_scores = isolation_forest.decision_function(X)


print("\nIsolation Forest completed!")


# --------------------------------------------------
# 5. LOF
# --------------------------------------------------

lof = LocalOutlierFactor(
    n_neighbors=20,
    contamination=0.05
)

lof_predictions = lof.fit_predict(X)

lof_labels = [
    "Normal" if prediction == 1 else "Suspicious"
    for prediction in lof_predictions
]

print("LOF completed!")


# --------------------------------------------------
# 6. One-Class SVM
# --------------------------------------------------

one_class_svm = OneClassSVM(
    kernel="rbf",
    gamma="scale",
    nu=0.05
)

svm_predictions = one_class_svm.fit_predict(X)

svm_labels = [
    "Normal" if prediction == 1 else "Suspicious"
    for prediction in svm_predictions
]

print("One-Class SVM completed!")


# --------------------------------------------------
# 7. Model comparison
# --------------------------------------------------

comparison = pd.DataFrame({
    "Isolation_Forest": isolation_labels,
    "LOF": lof_labels,
    "One_Class_SVM": svm_labels
})

print("\nModel Comparison:")
print(comparison.apply(pd.Series.value_counts).fillna(0))


# --------------------------------------------------
# 8. Save Isolation Forest model
# --------------------------------------------------

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

dump(isolation_forest, MODEL_PATH)

print("\nIsolation Forest model saved successfully!")
print("Saved to:", MODEL_PATH)


# --------------------------------------------------
# 9. Save Isolation Forest predictions
# --------------------------------------------------

prediction_results = data.copy()


prediction_results["prediction"] = isolation_labels
prediction_results["anomaly_score"] = anomaly_scores

prediction_results.to_csv(
    PREDICTIONS_PATH,
    index=False
)

print("\nPrediction results saved to:")
print(PREDICTIONS_PATH)


# --------------------------------------------------
# 10. Display sample results
# --------------------------------------------------

print("\nSample Isolation Forest results:")
print(prediction_results.head(10))


print("\nTask 3 completed successfully!")