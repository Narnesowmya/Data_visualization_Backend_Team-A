"""
Task 11: Security Intelligence REST API Router
Endpoints:
  - GET /api/v1/attack-chains
  - GET /api/v1/recommendations/{incident_id}
"""
from fastapi import APIRouter, Path, HTTPException, status
from typing import List, Dict, Any
from services.intelligence_service import IntelligenceService
from models.incident_model import AttackChainModel

router = APIRouter(tags=["Security Intelligence & Attack Chains"])

@router.get(
    "/attack-chains",
    response_model=List[AttackChainModel],
    status_code=status.HTTP_200_OK,
    summary="Get Correlated Multi-Stage Attack Chains",
    description="Retrieves all multi-stage attack chains identified by correlating events across multiple MITRE ATT&CK tactics."
)
def get_attack_chains():
    try:
        return IntelligenceService.get_all_attack_chains()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving attack chains: {str(e)}")

@router.get(
    "/recommendations/{incident_id}",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get Recommended Response Actions for Incident",
    description="Retrieves actionable SOC response recommendations for an incident based on threat type and MITRE ATT&CK mapping."
)
def get_incident_recommendations(
    incident_id: str = Path(..., description="Unique Incident ID e.g. INC-001")
):
    try:
        recs = IntelligenceService.get_incident_recommendations(incident_id)
        if recs is None:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
        return recs
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving recommendations: {str(e)}")

