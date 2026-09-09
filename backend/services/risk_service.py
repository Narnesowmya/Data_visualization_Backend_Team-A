"""
Risk Engine Service (Task 6 & Task 11)
"""
from typing import List, Dict, Any
from risk import calculate_risk, calculate_risk_batch, prioritize_incidents
from database import get_incidents

class RiskService:
    @staticmethod
    def calculate_single(event_data: Dict[str, Any]) -> Dict[str, Any]:
        return calculate_risk(event_data)

    @staticmethod
    def calculate_batch(events_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return calculate_risk_batch(events_data)

    @staticmethod
    def get_high_risk_events(min_score: float = 70.0, limit: int = 50) -> List[Dict[str, Any]]:
        return get_incidents(min_risk_score=min_score, limit=limit)
