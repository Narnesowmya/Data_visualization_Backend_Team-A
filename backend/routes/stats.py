from fastapi import APIRouter, Depends

from services.stats_service import get_dashboard_stats
from models.schemas import StatsOut
from utils.auth import get_api_key

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("", response_model=StatsOut)
async def get_stats(_api_key=Depends(get_api_key)):
    """Return dashboard statistics (total events, critical alerts, etc.)."""
    return await get_dashboard_stats()
