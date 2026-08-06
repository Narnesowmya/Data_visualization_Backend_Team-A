from typing import Optional
from database.mongo import assets_collection


async def list_assets(asset_type: Optional[str] = None, criticality: Optional[str] = None,
                       limit: int = 100, offset: int = 0):
    query = {}
    if asset_type:
        query["asset_type"] = asset_type
    if criticality:
        query["criticality"] = criticality

    cursor = (
        assets_collection.find(query)
        .sort("created_at", -1)
        .skip(offset)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)
