"""
Milestone 2 Backward-Compatibility Prediction API Router
Endpoints:
  - GET /api/v1/predictions
"""
from fastapi import APIRouter, Query, HTTPException, status
from typing import List, Dict, Any
from database import get_incidents

router = APIRouter(prefix="/predictions", tags=["ML Predictions (Milestone 2)"])

@router.get(
    "",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Get ML Threat Predictions",
    description="Retrieves threat detection predictions produced by Milestone 2 ML model pipeline."
)
def get_predictions(
    limit: int = Query(50, ge=1, le=500, description="Page limit")
):
    try:
        incidents = get_incidents(limit=limit)
        results = []
        for inc in incidents:
            results.append({
                "event_id": inc["event_ids"][0] if inc.get("event_ids") else "EVT-001",
                "prediction": "Suspicious" if inc.get("risk_score", 0) > 40 else "Normal",
                "threat_type": inc.get("threat_type"),
                "confidence_score": round(inc.get("explainability", {}).get("ml_confidence_score", 90.0), 1),
                "severity": inc.get("priority"),
                "incident_id": inc.get("incident_id")
            })
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving predictions: {str(e)}")
