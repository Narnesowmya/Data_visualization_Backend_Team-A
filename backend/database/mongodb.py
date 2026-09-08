import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        ".env"
    )
)

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI is not configured in .env")


client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

db = client["ThreatDashboardDB"]


def test_connection():
    client.admin.command("ping")
    return True

def get_database():
    return db