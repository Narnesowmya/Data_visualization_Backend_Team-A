from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


def doc_to_id(doc: dict) -> dict:
    """Convert Mongo _id to API id string safely."""
    doc = dict(doc)
    _id = doc.pop("_id", None)
    doc["id"] = str(_id) if _id is not None else ""
    return doc


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    severity: str
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    status: str


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[str] = None
    criticality: Optional[str] = None
    owner: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[datetime] = None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    cve_id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    status: Optional[str] = None
    asset_id: Optional[str] = None
    discovered_at: Optional[datetime] = None


class ThreatOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    indicator: Optional[str] = None
    threat_type: str
    confidence: Optional[int] = None
    mitre_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None


class StatsOut(BaseModel):
    total_events: int
    critical_alerts: int
    open_events: int
    resolved_events: int
    total_assets: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    active_threats: int