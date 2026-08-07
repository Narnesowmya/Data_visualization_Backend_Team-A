from typing import Optional
from database.mongo import threats_collection


async def list_threats(threat_type: Optional[str] = None, tactic: Optional[str] = None,
                        limit: int = 100, offset: int = 0):
    query = {}
    if threat_type:
        query["threat_type"] = threat_type
    if tactic:
        query["tactic"] = tactic

    cursor = (
        threats_collection.find(query)
        .skip(offset)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)