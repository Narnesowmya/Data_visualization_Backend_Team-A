"""
Task 11: Risk Scoring REST API Router
Endpoints:
  - POST /api/v1/risk/calculate
  - GET  /api/v1/risk/high
  - GET  /api/v1/risk/summary
"""
from fastapi import APIRouter, Query, HTTPException, status
from typing import List, Optional, Dict, Any
from models.risk_model import RiskCalculateRequest, RiskCalculateResponse
from models.incident_model import IncidentSummaryModel
from services.risk_service import RiskService
from services.incident_service import IncidentService

router = APIRouter(prefix="/risk", tags=["Risk Prioritization & Intelligence"])

@router.post(
    "/calculate",
    response_model=RiskCalculateResponse,
    status_code=status.HTTP_200_OK,
    summary="Calculate Risk Score for Security Event",
    description="Calculates a composite risk score (0-100) using Threat Severity (25%), ML Confidence (25%), Asset Criticality (20%), Vulnerability Exposure (20%), and Threat Intelligence (10%)."
)
def calculate_risk_score(request: RiskCalculateRequest):
    try:
        event_data = request.model_dump()
        result = RiskService.calculate_single(event_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error calculating risk score: {str(e)}")

@router.get(
    "/high",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Get High and Critical Risk Security Incidents",
    description="Retrieves prioritized high and critical security incidents above a specified risk score threshold (default: 70.0)."
)
def get_high_risk_incidents(
    min_score: float = Query(70.0, ge=0.0, le=100.0, description="Minimum risk score threshold"),
    limit: int = Query(50, ge=1, le=1000, description="Maximum number of incidents to return")
):
    try:
        return RiskService.get_high_risk_events(min_score=min_score, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching high risk incidents: {str(e)}")

@router.get(
    "/summary",
    response_model=IncidentSummaryModel,
    status_code=status.HTTP_200_OK,
    summary="Get Overall Risk Intelligence Summary",
    description="Aggregates security risk metrics including total incidents, priority counts, status counts, average risk score, and top impacted assets."
)
def get_risk_summary():
    try:
        return IncidentService.get_summary()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching risk summary: {str(e)}")
