import os
import certifi
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import PyMongoError

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is not set in environment")

MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "ThreatDashboardDB")

client = AsyncIOMotorClient(
    MONGODB_URI,
    tls=True,
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=10000,
)

db = client[MONGODB_DB_NAME]

# Collections
api_keys_collection = db["api_keys"]
events_collection = db["events"]  
assets_collection = db["assets"]
vulnerabilities_collection = db["vulnerabilities"]
threats_collection = db["threats"]          

async def create_indexes():
    """Call once at app startup."""
    try:
        await api_keys_collection.create_index("key_hash", unique=True)
        await events_collection.create_index([("created_at", -1)])
        await assets_collection.create_index([("created_at", -1)])
        await vulnerabilities_collection.create_index([("discovered_at", -1)])
        await threats_collection.create_index([("detected_at", -1)])
        print("MongoDB indexes ensured successfully.")
    except PyMongoError as e:
        print(f"MongoDB index creation failed: {e}")
        raise