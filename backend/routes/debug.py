from fastapi import APIRouter, Depends
from database.mongo import (
    events_collection,
    assets_collection,
    vulnerabilities_collection,
    threats_collection,
)
from utils.auth import get_api_key

router = APIRouter(prefix="/debug", tags=["Debug"])


@router.get("/counts")
async def get_counts(_api_key=Depends(get_api_key)):
    return {
        "events": await events_collection.count_documents({}),
        "assets": await assets_collection.count_documents({}),
        "vulnerabilities": await vulnerabilities_collection.count_documents({}),
        "threats": await threats_collection.count_documents({}),
    }