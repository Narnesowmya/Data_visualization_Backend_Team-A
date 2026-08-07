from mongo_connection import db

collections = [
    "processed_logs",
    "enriched_events",
    "threat_mappings",
    "severity_levels",
    "risk_labels",
    "assets",
    "vulnerabilities"
]
existing = db.list_collection_names()

for collection in collections:
    if collection not in existing:
        db.create_collection(collection)
        print(f"✅ Created: {collection}")
    else:
        print(f"⚠ Already exists: {collection}")

print("\n🎉 Database setup completed!")