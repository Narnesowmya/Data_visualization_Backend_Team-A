"""
Milestone 2 Backward-Compatibility Anomaly Detection API Router
Endpoints:
  - GET /api/v1/anomalies
"""
from fastapi import APIRouter, Query, HTTPException, status
from typing import List, Dict, Any
from database import get_incidents

router = APIRouter(prefix="/anomalies", tags=["Anomaly Detection (Milestone 2)"])

@router.get(
    "",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Get Detected Anomaly Events",
    description="Retrieves security events flagged as anomalous by the Isolation Forest model."
)
def get_anomalies(
    limit: int = Query(50, ge=1, le=500, description="Page limit")
):
    try:
        incidents = get_incidents(min_risk_score=60.0, limit=limit)
        results = []
        for inc in incidents:
            results.append({
                "event_id": inc["event_ids"][0] if inc.get("event_ids") else "EVT-001",
                "anomaly_score": round(-0.5 - (inc.get("risk_score", 50)/200.0), 3),
                "is_anomaly": True,
                "asset_id": inc.get("asset_id"),
                "threat_type": inc.get("threat_type"),
                "risk_score": inc.get("risk_score")
            })
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving anomalies: {str(e)}")
