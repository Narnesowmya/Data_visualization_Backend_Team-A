from typing import Optional
from database.mongo import events_collection


async def list_events(severity: Optional[str] = None, status: Optional[str] = None,
                       limit: int = 100, offset: int = 0):
    query = {}
    if severity:
        query["severity"] = severity
    if status:
        query["status"] = status

    cursor = (
        events_collection.find(query)
        .sort("timestamp", -1)
        .skip(offset)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)
