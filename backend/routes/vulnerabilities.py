from typing import Optional, List
from fastapi import APIRouter, Depends, Query

from services.vulnerability_service import list_vulnerabilities
from models.schemas import VulnerabilityOut, doc_to_id
from utils.auth import get_api_key

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=List[VulnerabilityOut])
async def get_vulnerabilities(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    _api_key=Depends(get_api_key),
):
    """Return vulnerability details."""
    docs = await list_vulnerabilities(severity, status, asset_id, limit, offset)
    return [doc_to_id(d) for d in docs]
