from typing import Optional, List
from fastapi import APIRouter, Depends, Query

from services.event_service import list_events
from models.schemas import SecurityEventOut, doc_to_id
from utils.auth import get_api_key

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=List[SecurityEventOut])
async def get_events(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    _api_key=Depends(get_api_key),
):
    """Return security event details."""
    docs = await list_events(severity, status, limit, offset)
    return [doc_to_id(d) for d in docs]