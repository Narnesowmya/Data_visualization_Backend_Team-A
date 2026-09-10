"""
Security Intelligence Service (Task 8, Task 9, Task 11)
"""
from typing import List, Dict, Any, Optional
from database import get_attack_chains, get_incident_by_id
from risk import get_recommendations_for_threat

class IntelligenceService:
    @staticmethod
    def get_all_attack_chains() -> List[Dict[str, Any]]:
        return get_attack_chains()

    @staticmethod
    def get_incident_recommendations(incident_id: str) -> Optional[Dict[str, Any]]:
        incident = get_incident_by_id(incident_id)
        if not incident:
            return None
        
        return {
            "incident_id": incident_id,
            "threat_type": incident.get("threat_type"),
            "priority": incident.get("priority"),
            "asset_id": incident.get("asset_id"),
            "mitre_techniques": incident.get("mitre_techniques", []),
            "recommendations": incident.get("recommendations", [])
        }

