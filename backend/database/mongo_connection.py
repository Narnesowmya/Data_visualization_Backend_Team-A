from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()

# Read MongoDB URI
MONGO_URI = os.getenv("MONGO_URI")

# Connect to MongoDB Atlas
client = MongoClient(MONGO_URI)

# Access (or create) a database
db = client["ThreatDashboardDB"]

# Test the connection
client.admin.command("ping")

print("✅ Successfully connected to MongoDB Atlas!")