from typing import Optional, List
from fastapi import APIRouter, Depends, Query

from services.threat_service import list_threats
from models.schemas import ThreatOut, doc_to_id
from utils.auth import get_api_key

router = APIRouter(prefix="/threats", tags=["Threats"])


@router.get("", response_model=List[ThreatOut])
async def get_threats(
    threat_type: Optional[str] = Query(None, description="e.g. Malware, Phishing, Ransomware, Brute Force"),
    tactic: Optional[str] = Query(None, description="e.g. Initial Access, Execution, Reconnaissance"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    _api_key=Depends(get_api_key),
):
    """Return threat-related data."""
    docs = await list_threats(threat_type, tactic, limit, offset)
    return [doc_to_id(d) for d in docs]