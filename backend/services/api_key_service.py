"""
Core API key logic: generating, hashing, verifying, and revoking keys.
Import from here in both the CLI scripts and the FastAPI auth dependency,
so there's a single source of truth.
"""
import hashlib
import secrets
from datetime import datetime, timezone

from database.mongo import api_keys_collection


def hash_key(raw_key: str) -> str:
    """One-way hash — we only ever store/compare hashes, never the raw key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


async def create_api_key(name: str) -> str:
    """Generate a new key, store its hash, return the plaintext ONCE."""
    raw_key = "sk_" + secrets.token_urlsafe(32)
    prefix = raw_key[:11]

    await api_keys_collection.insert_one(
        {
            "name": name,
            "key_prefix": prefix,
            "key_hash": hash_key(raw_key),
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "last_used_at": None,
        }
    )
    return raw_key


async def verify_api_key(raw_key: str) -> dict | None:
    """Look up a key by its hash. Returns the document if valid+active, else None.
    Also updates last_used_at on success."""
    record = await api_keys_collection.find_one({"key_hash": hash_key(raw_key)})
    if record is None or not record.get("is_active", False):
        return None

    await api_keys_collection.update_one(
        {"_id": record["_id"]},
        {"$set": {"last_used_at": datetime.now(timezone.utc)}},
    )
    return record


async def revoke_api_key(name_or_prefix: str) -> bool:
    """Deactivate a key by name or prefix. Returns True if a key was found."""
    result = await api_keys_collection.update_one(
        {"$or": [{"name": name_or_prefix}, {"key_prefix": name_or_prefix}]},
        {"$set": {"is_active": False}},
    )
    return result.matched_count > 0
