from typing import Optional, List
from fastapi import APIRouter, Depends, Query

from services.asset_service import list_assets
from models.schemas import AssetOut, doc_to_id
from utils.auth import get_api_key

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=List[AssetOut])
async def get_assets(
    asset_type: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    _api_key=Depends(get_api_key),
):
    """Return asset information."""
    docs = await list_assets(asset_type, criticality, limit, offset)
    return [doc_to_id(d) for d in docs]
