from mongo_connection import db

collection = db["severity_levels"]

# Remove old records
collection.delete_many({})

severity_data = [
    {
        "severity": "Critical",
        "score": 4,
        "description": "Highest priority security event"
    },
    {
        "severity": "High",
        "score": 3,
        "description": "High priority security event"
    },
    {
        "severity": "Medium",
        "score": 2,
        "description": "Moderate priority security event"
    },
    {
        "severity": "Low",
        "score": 1,
        "description": "Low priority security event"
    }
]

result = collection.insert_many(severity_data)

print(f"✅ Inserted {len(result.inserted_ids)} severity levels.")