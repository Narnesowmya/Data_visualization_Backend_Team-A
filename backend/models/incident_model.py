"""
Pydantic Data Models for Incident Management (Task 10 & 11)
"""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class IncidentStatusEnum(str, Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"

class RiskLevelEnum(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MODERATE = "Moderate"
    MEDIUM = "Medium"
    LOW = "Low"

class ExplainabilityModel(BaseModel):
    severity_weight_pct: float = Field(25.0, description="Weight percentage for threat severity")
    severity_score: float = Field(..., description="Normalized severity score (0-100)")
    ml_confidence_weight_pct: float = Field(25.0, description="Weight percentage for ML confidence")
    ml_confidence_score: float = Field(..., description="Normalized ML confidence score (0-100)")
    asset_criticality_weight_pct: float = Field(20.0, description="Weight percentage for asset criticality")
    asset_criticality_score: Optional[float] = Field(None, description="Normalized asset criticality score (0-100), or None if unverified/Unknown")
    vulnerability_weight_pct: float = Field(20.0, description="Weight percentage for vulnerability/CVSS")
    vulnerability_score: float = Field(..., description="Normalized vulnerability score (0-100)")
    threat_intel_weight_pct: float = Field(10.0, description="Weight percentage for threat intelligence/IOC")
    threat_intel_score: float = Field(..., description="Normalized threat intelligence score (0-100)")
    reasons: List[str] = Field(default_factory=list, description="Key factors contributing to the risk score")


class AttackStageModel(BaseModel):
    stage_order: int = Field(..., description="Sequential attack-chain stage number")
    tactic: str = Field(..., description="MITRE ATT&CK tactic")
    technique: str = Field(..., description="MITRE ATT&CK technique ID")
    technique_name: Optional[str] = Field(None, description="Human-readable technique name")
    description: Optional[str] = Field(None, description="Stage description")

class RelatedEventModel(BaseModel):
    event_id: str = Field(..., description="Security event identifier")
    timestamp: str = Field(..., description="Event timestamp")
    source_ip: Optional[str] = Field(None, description="Event source IP address")
    description: str = Field(..., description="Human-readable description of the related event")

class AttackChainModel(BaseModel):
    attack_chain_id: str
    correlation_id: str
    event_ids: str
    event_count: int
    correlation_rule: str
    mitre_techniques: str
    mitre_tactics: str
    attack_stages: str
    risk_score: float
    risk_level: str
    confidence: float
    start_time: str
    end_time: str
    window_minutes: float
    asset_name: str
    source_ip: str

class IncidentModel(BaseModel):
    incident_id: str = Field(..., description="Unique Incident identifier e.g. INC-001")
    event_ids: List[str] = Field(..., description="List of correlated event IDs")
    threat_type: str = Field(..., description="Identified threat classification or attack chain")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Calculated composite risk score (0-100)")
    risk_level: str = Field(..., description="Risk Level classification e.g. Critical, High, Moderate, Medium, Low")
    priority: str = Field(..., description="Priority action: Immediate Investigation, Investigate Soon, Review When Possible, Monitor, or No Action Needed")
    asset_id: str = Field(..., description="Target asset ID or asset name e.g. DB-001")
    affected_user: Optional[str] = Field(None, description="Impacted account/user ID")
    source_ip: Optional[str] = Field(None, description="Attacker or source IP address")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK technique IDs")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK tactics")
    status: IncidentStatusEnum = Field(IncidentStatusEnum.OPEN, description="Current SOC incident lifecycle status")
    recommendations: List[str] = Field(default_factory=list, description="Recommended SOC response actions")
    attack_chain: List[AttackStageModel] = Field(default_factory=list, description="Correlated attack progression stages")
    related_events: List[RelatedEventModel] = Field(default_factory=list, description="Detailed correlated events for investigation context")
    explainability: Optional[ExplainabilityModel] = Field(None, description="Explainable risk breakdown")
    event_count: int = Field(1, description="Number of correlated security events")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class StatusUpdateModel(BaseModel):
    status: IncidentStatusEnum = Field(..., description="Updated incident status")

class IncidentSummaryModel(BaseModel):
    total_incidents: int
    open_incidents: int
    investigating_incidents: int
    resolved_incidents: int
    false_positive_incidents: int
    priority_counts: Dict[str, int]
    status_counts: Dict[str, int]
    average_risk_score: float
    top_assets: List[Dict[str, Any]]
