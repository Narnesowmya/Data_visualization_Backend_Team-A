import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from config import settings

logger = logging.getLogger(__name__)

_mongo_client = None
_db = None
_is_available = False


def init_mongodb():
    global _mongo_client, _db, _is_available

    try:
        _mongo_client = MongoClient(
            settings.MONGO_URI,
            serverSelectionTimeoutMS=2000,
            connectTimeoutMS=2000,
        )

        _mongo_client.admin.command("ping")

        _db = _mongo_client[settings.DATABASE_NAME]
        _is_available = True

        logger.info("M3 MongoDB connection established.")
    except Exception as exc:
        _is_available = False
        _db = None
        logger.warning("M3 MongoDB unavailable: %s", exc)


def is_mongodb_available():
    return _is_available


def get_database():
    return _db


init_mongodb()