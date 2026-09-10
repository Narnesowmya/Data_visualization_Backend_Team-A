"""
Incident Business Logic Service (Task 10 & Task 11)
"""
from typing import List, Dict, Any, Optional
from database import (
    get_incidents,
    get_incident_by_id,
    update_incident_status,
    get_risk_summary,
    save_incident
)
from services.event_context import enrich_incident, enrich_incidents

class IncidentService:
    @staticmethod
    def list_incidents(
        priority: Optional[str] = None,
        status: Optional[str] = None,
        asset_id: Optional[str] = None,
        threat_type: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        limit: int = 50,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        incidents = get_incidents(
            priority=priority,
            status=status,
            asset_id=asset_id,
            threat_type=threat_type,
            min_risk_score=min_risk_score,
            limit=limit,
            skip=skip
        )
        return enrich_incidents(incidents)

    @staticmethod
    def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
        incident = get_incident_by_id(incident_id)
        return enrich_incident(incident) if incident else None

    @staticmethod
    def update_status(incident_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        valid_statuses = {"Open", "Investigating", "Resolved", "False Positive"}
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status '{new_status}'. Must be one of {valid_statuses}")
        updated = update_incident_status(incident_id, new_status)
        return enrich_incident(updated) if updated else None

    @staticmethod
    def get_summary() -> Dict[str, Any]:
        return get_risk_summary()

    @staticmethod
    def create_incident(incident_data: Dict[str, Any]) -> str:
        return save_incident(incident_data)
