"""
Pydantic Data Models for Risk Score Engine (Task 6 & 11)
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from .incident_model import ExplainabilityModel, RiskLevelEnum

class RiskCalculateRequest(BaseModel):
    event_id: Optional[str] = Field("EVT-CUSTOM", description="Event ID")
    severity: Optional[Any] = Field("High", description="Threat severity string or score")
    ml_confidence: Optional[float] = Field(90.0, description="ML prediction confidence score (0-100)")
    asset_criticality: Optional[Any] = Field("Critical", description="Asset criticality label or score")
    cvss_score: Optional[float] = Field(8.5, description="CVSS vulnerability score (0-10)")
    ioc_status: Optional[str] = Field("Malicious", description="Threat intelligence / IOC status")
    failed_login_attempts: Optional[int] = Field(0, description="Number of failed logins if applicable")

class RiskCalculateResponse(BaseModel):
    event_id: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Calculated composite risk score (0-100)")
    risk_level: str = Field(..., description="Risk level classification e.g. Critical, High, Moderate, Medium, Low")
    priority: str = Field(..., description="Priority action: Immediate Investigation, Investigate Soon, Review When Possible, Monitor, or No Action Needed")
    reasons: List[str]
    explainability: ExplainabilityModel
    calculated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

