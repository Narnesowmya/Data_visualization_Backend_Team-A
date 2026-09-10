import json
import pickle
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from database.mongodb import get_database


router = APIRouter(tags=["Milestone 2 - Prediction APIs"])


# =========================================================
# PATHS
# =========================================================

BACKEND_ROOT = Path(__file__).resolve().parent.parent

ML_DIR = BACKEND_ROOT / "ml"
DATA_DIR = BACKEND_ROOT / "data"

ANOMALY_FILE = ML_DIR / "anomaly_predictions.csv"
MODEL_FILE = ML_DIR / "model.pkl"
ARTIFACT_DIR = ML_DIR / "artifacts"

ENCODER_FILE = ARTIFACT_DIR / "encoders.pkl"
SCALER_FILE = ARTIFACT_DIR / "scaler.pkl"
FEATURE_FILE = ARTIFACT_DIR / "feature_columns.json"

THREAT_FILE = DATA_DIR / "threat_classification_with_confidence.csv"


# =========================================================
# DATABASE
# =========================================================

db = get_database()
prediction_collection = db["threat_predictions"]


# =========================================================
# LOAD DATA
# =========================================================

try:
    anomaly_df = pd.read_csv(ANOMALY_FILE)
except Exception:
    anomaly_df = pd.DataFrame()


try:
    threat_df = pd.read_csv(THREAT_FILE)
except Exception:
    threat_df = pd.DataFrame()


# =========================================================
# LOAD MODEL + ARTIFACTS
# =========================================================

model = None
encoders = None
scaler = None
feature_columns = None
model_load_error = None

try:
    model = joblib.load(MODEL_FILE)

    with open(ENCODER_FILE, "rb") as f:
        encoders = pickle.load(f)

    with open(SCALER_FILE, "rb") as f:
        scaler = pickle.load(f)

    with open(FEATURE_FILE, "r") as f:
        feature_columns = json.load(f)

except Exception as e:
    model_load_error = str(e)


# =========================================================
# REQUEST MODEL
# =========================================================

class PredictionRequest(BaseModel):
    event_type: str = Field(..., description="Type of security event")
    severity: str = Field(..., description="Low, Medium, High or Critical")
    protocol: str = Field(..., description="Network protocol")
    failed_login_attempts: float = Field(0, ge=0)
    malware_detected: str = Field(..., description="Yes or No")
    cvss_score: float = Field(..., ge=0, le=10)
    os: str = Field(..., description="Operating system")
    department: str = Field(..., description="Department")


# =========================================================
# PAGINATION
# =========================================================

def validate_pagination(skip: int, limit: int):
    if skip < 0:
        raise HTTPException(status_code=422, detail="skip must be >= 0")

    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 1 and 100"
        )


# =========================================================
# INPUT ENCODING
# =========================================================

def encode_input(request: PredictionRequest):

    df = pd.DataFrame([{
        "failed_login_attempts": request.failed_login_attempts,
        "cvss_score": request.cvss_score,
        "malware_detected": request.malware_detected,
        "severity": request.severity,
        "event_type": request.event_type,
        "protocol": request.protocol,
        "os": request.os,
        "department": request.department
    }])

    # Malware
    malware_value = str(
        df.loc[0, "malware_detected"]
    ).strip().lower()

    malware_map = {
        "yes": 1,
        "true": 1,
        "1": 1,
        "no": 0,
        "false": 0,
        "0": 0
    }

    if malware_value not in malware_map:
        raise HTTPException(
            status_code=422,
            detail="malware_detected must be Yes or No"
        )

    df["malware_detected"] = malware_map[malware_value]

    # Severity
    severity_value = str(
        df.loc[0, "severity"]
    ).strip().lower()

    severity_scores = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    if severity_value not in severity_scores:
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid severity. Use one of: "
                "Low, Medium, High, Critical"
            )
        )

    df["severity_score"] = severity_scores[severity_value]

    # Categorical encoders
    categorical_columns = [
        "event_type",
        "protocol",
        "os",
        "department"
    ]

    for column in categorical_columns:

        encoder = encoders.get(column)

        if encoder is None:
            raise HTTPException(
                status_code=500,
                detail=f"Encoder not available for {column}"
            )

        value = str(df.loc[0, column])

        try:
            if value in encoder.classes_:
                encoded_value = encoder.transform([value])[0]
            else:
                encoded_value = -1
        except Exception:
            encoded_value = -1

        df[f"{column}_enc"] = encoded_value

    # Scale numeric features
    numeric_columns = [
        "failed_login_attempts",
        "cvss_score"
    ]

    df[numeric_columns] = scaler.transform(
        df[numeric_columns]
    )

    if feature_columns is None:
        raise HTTPException(
            status_code=500,
            detail="Feature configuration is not available"
        )

    missing_features = [
        feature
        for feature in feature_columns
        if feature not in df.columns
    ]

    if missing_features:
        raise HTTPException(
            status_code=500,
            detail=f"Missing model features: {missing_features}"
        )

    return df[feature_columns].copy()


# =========================================================
# CONFIDENCE SCORING
# =========================================================

def calculate_threat_confidence(
    anomaly_score,
    cvss_score,
    failed_login_attempts,
    malware_detected,
    severity
):

    evidence = []
    weights = []

    anomaly_evidence = max(
        0,
        min(1, 0.5 - anomaly_score)
    )

    evidence.append(anomaly_evidence)
    weights.append(0.40)

    cvss_evidence = max(
        0,
        min(1, cvss_score / 10)
    )

    evidence.append(cvss_evidence)
    weights.append(0.15)

    failed_login_evidence = max(
        0,
        min(1, failed_login_attempts / 10)
    )

    evidence.append(failed_login_evidence)
    weights.append(0.10)

    malware_evidence = (
        1.0
        if str(malware_detected).strip().lower()
        in ["yes", "true", "1"]
        else 0.0
    )

    evidence.append(malware_evidence)
    weights.append(0.025)

    severity_scores = {
        "low": 0.25,
        "medium": 0.50,
        "high": 0.75,
        "critical": 1.00
    }

    severity_evidence = severity_scores.get(
        str(severity).strip().lower(),
        0.0
    )

    evidence.append(severity_evidence)
    weights.append(0.15)

    total_weight = sum(weights)

    confidence = sum(
        value * weight
        for value, weight in zip(evidence, weights)
    ) / total_weight

    return round(confidence * 100, 2)


# =========================================================
# GET /m2-health
# =========================================================

@router.get("/m2-health")
def milestone2_health():

    try:
        db.command("ping")
        mongodb_status = True
    except Exception:
        mongodb_status = False

    return {
        "status": "healthy" if mongodb_status else "degraded",
        "mongodb_connected": mongodb_status,
        "anomaly_records": len(anomaly_df),
        "threat_records": len(threat_df),
        "mongodb_prediction_records":
            prediction_collection.count_documents({}),
        "model_loaded": model is not None,
        "model_load_error": model_load_error
    }


# =========================================================
# POST /predict
# =========================================================

@router.post("/predict")
def predict(request: PredictionRequest):

    if model is None:
        raise HTTPException(
            status_code=500,
            detail=f"ML model is not loaded: {model_load_error}"
        )

    if encoders is None or scaler is None:
        raise HTTPException(
            status_code=500,
            detail="ML preprocessing artifacts are not loaded"
        )

    X = encode_input(request)

    prediction_value = model.predict(X)[0]

    anomaly_score = float(
        model.decision_function(X)[0]
    )

    prediction = (
        "Suspicious"
        if prediction_value == -1
        else "Normal"
    )

    confidence_score = calculate_threat_confidence(
        anomaly_score=anomaly_score,
        cvss_score=request.cvss_score,
        failed_login_attempts=request.failed_login_attempts,
        malware_detected=request.malware_detected,
        severity=request.severity
    )

    event_id = (
        "API-" +
        uuid.uuid4().hex[:8].upper()
    )

    prediction_timestamp = datetime.now(
        timezone.utc
    )

    prediction_document = {
        "event_id": event_id,
        "prediction": prediction,
        "threat_type": request.event_type,
        "confidence_score": confidence_score,
        "anomaly_score": anomaly_score,
        "severity": request.severity,
        "prediction_timestamp": prediction_timestamp,
        "model_version": "IF_v1"
    }

    try:
        prediction_collection.insert_one(
            prediction_document
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to store prediction: {str(e)}"
        )

    return {
        "status": "success",
        "event_id": event_id,
        "prediction": prediction,
        "confidence_score": confidence_score,
        "anomaly_score": anomaly_score,
        "severity": request.severity,
        "threat_type": request.event_type,
        "model_version": "IF_v1"
    }


# =========================================================
# GET /predictions
# =========================================================

@router.get("/predictions")
def get_predictions(
    skip: int = 0,
    limit: int = 50
):

    validate_pagination(skip, limit)

    total_records = prediction_collection.count_documents({})

    records = list(
        prediction_collection
        .find({}, {"_id": 0})
        .sort("event_id", 1)
        .skip(skip)
        .limit(limit)
    )

    return {
        "status": "success",
        "total_records": total_records,
        "returned_records": len(records),
        "skip": skip,
        "limit": limit,
        "predictions": records
    }


# =========================================================
# GET /predictions/{event_id}
# =========================================================

@router.get("/predictions/{event_id}")
def get_prediction(event_id: str):

    prediction = prediction_collection.find_one(
        {"event_id": event_id},
        {"_id": 0}
    )

    if prediction is None:
        raise HTTPException(
            status_code=404,
            detail=f"Prediction not found for event_id: {event_id}"
        )

    return {
        "status": "success",
        "prediction": prediction
    }


# =========================================================
# GET /anomalies
# =========================================================

@router.get("/anomalies")
def get_anomalies(
    skip: int = 0,
    limit: int = 50
):

    validate_pagination(skip, limit)

    if anomaly_df.empty:
        raise HTTPException(
            status_code=500,
            detail="Anomaly prediction data is not available"
        )

    total_records = len(anomaly_df)

    result = anomaly_df.iloc[
        skip:skip + limit
    ]

    records = (
        result
        .fillna("")
        .to_dict(orient="records")
    )

    return {
        "status": "success",
        "total_records": total_records,
        "returned_records": len(records),
        "skip": skip,
        "limit": limit,
        "anomalies": records
    }



# =========================================================
# GET /model-performance
# =========================================================

@router.get("/model-performance")
def model_performance():

    if anomaly_df.empty:
        raise HTTPException(
            status_code=500,
            detail="Anomaly prediction data is not available"
        )

    total = len(anomaly_df)

    normal_count = int(
        (
            anomaly_df["prediction"]
            .astype(str)
            .str.lower()
            == "normal"
        ).sum()
    )

    suspicious_count = int(
        (
            anomaly_df["prediction"]
            .astype(str)
            .str.lower()
            == "suspicious"
        ).sum()
    )

    return {
        "status": "success",
        "model": "Isolation Forest",
        "model_version": "IF_v1",
        "model_type": "Unsupervised anomaly detection",
        "total_predictions": total,
        "normal_predictions": normal_count,
        "suspicious_predictions": suspicious_count,
        "suspicious_rate": (
            round(
                (suspicious_count / total) * 100,
                2
            )
            if total > 0
            else 0
        ),
        "note": (
            "Precision, recall and F1-score are not reported "
            "here because this endpoint does not assume reliable "
            "ground-truth labels for the unsupervised anomaly model."
        )
    }


# =========================================================
# GET /threat-summary
# =========================================================

@router.get("/threat-summary")
def threat_summary():

    total_predictions = prediction_collection.count_documents({})

    normal_count = prediction_collection.count_documents({
        "prediction": "Normal"
    })

    suspicious_count = prediction_collection.count_documents({
        "prediction": "Suspicious"
    })

    severity_counts = {}

    for severity in [
        "Low",
        "Medium",
        "High",
        "Critical"
    ]:
        severity_counts[severity] = (
            prediction_collection.count_documents({
                "severity": severity
            })
        )

    return {
        "status": "success",
        "total_predictions": total_predictions,
        "normal_predictions": normal_count,
        "suspicious_predictions": suspicious_count,
        "severity_summary": severity_counts
    }


# =========================================================
# GET /summary
# =========================================================

@router.get("/summary")
def get_summary():

    if threat_df.empty:
        raise HTTPException(
            status_code=500,
            detail="Threat classification data is not available"
        )

    total_events = len(threat_df)

    if "prediction" in threat_df.columns:

        normal_events = int(
            (
                threat_df["prediction"]
                .astype(str)
                .str.lower()
                == "normal"
            ).sum()
        )

        anomalous_events = int(
            (
                threat_df["prediction"]
                .astype(str)
                .str.lower()
                == "suspicious"
            ).sum()
        )

    else:
        normal_events = 0
        anomalous_events = 0

    if "threat_level" in threat_df.columns:

        threat_levels = (
            threat_df["threat_level"]
            .astype(str)
            .str.strip()
            .str.lower()
        )

        critical_threats = int(
            (threat_levels == "critical").sum()
        )

        high_threats = int(
            (threat_levels == "high").sum()
        )

        medium_threats = int(
            (threat_levels == "medium").sum()
        )

        low_threats = int(
            (threat_levels == "low").sum()
        )

    else:
        critical_threats = 0
        high_threats = 0
        medium_threats = 0
        low_threats = 0

    return {
        "status": "success",
        "total_events": total_events,
        "normal_events": normal_events,
        "anomalous_events": anomalous_events,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats
    }