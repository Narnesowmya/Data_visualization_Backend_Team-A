"""
Task 11: Incident Management REST API Router
Endpoints:
  - GET   /api/v1/incidents
  - GET   /api/v1/incidents/{incident_id}
  - PATCH /api/v1/incidents/{incident_id}/status
"""
from fastapi import APIRouter, Query, Path, HTTPException, status
from typing import List, Optional, Dict, Any
from models.incident_model import IncidentModel, StatusUpdateModel, IncidentStatusEnum
from services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incident Management & SOC Operations"])

@router.get(
    "",
    response_model=List[IncidentModel],
    status_code=status.HTTP_200_OK,
    summary="Get Paginated Security Incidents List",
    description="Retrieves a list of SOC security incidents sorted by risk score descending with flexible filtering by priority, status, asset_id, or threat_type."
)
def list_incidents(
    priority: Optional[str] = Query(None, description="Filter by Priority: Immediate Investigation, Investigate Soon, Review When Possible, Monitor, No Action Needed"),
    status_filter: Optional[IncidentStatusEnum] = Query(None, alias="status", description="Filter by Status: Open, Investigating, Resolved, False Positive"),
    asset_id: Optional[str] = Query(None, description="Filter by Asset ID or Asset Name e.g. DB-001"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type substring e.g. Brute Force"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    skip: int = Query(0, ge=0, description="Offset skip count")
):
    try:
        status_val = status_filter.value if status_filter else None
        return IncidentService.list_incidents(
            priority=priority,
            status=status_val,
            asset_id=asset_id,
            threat_type=threat_type,
            limit=limit,
            skip=skip
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving incidents: {str(e)}")

@router.get(
    "/{incident_id}",
    response_model=IncidentModel,
    status_code=status.HTTP_200_OK,
    summary="Get Detailed Security Incident Information",
    description="Retrieves full details for a specific incident including event IDs, risk score explainability, MITRE techniques, attack chain, and response recommendations."
)
def get_incident_details(
    incident_id: str = Path(..., description="Unique Incident ID e.g. INC-001")
):
    incident = IncidentService.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return incident

@router.patch(
    "/{incident_id}/status",
    response_model=IncidentModel,
    status_code=status.HTTP_200_OK,
    summary="Update Security Incident Status",
    description="Updates the SOC status of an incident (Open, Investigating, Resolved, False Positive)."
)
def update_status(
    body: StatusUpdateModel,
    incident_id: str = Path(..., description="Unique Incident ID e.g. INC-001")
):
    try:
        updated = IncidentService.update_status(incident_id, body.status.value)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
        return updated
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating incident status: {str(e)}")
