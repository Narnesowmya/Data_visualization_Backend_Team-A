from fastapi import Header, HTTPException, status

from services.api_key_service import verify_api_key


async def get_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> dict:
    """FastAPI dependency: protects a route behind a valid X-API-Key header.
    Use it like: @router.get("/events") def get_events(_key = Depends(get_api_key)):"""
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    record = await verify_api_key(x_api_key)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")

    return record
