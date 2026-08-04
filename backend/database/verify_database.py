from mongo_connection import db

print("=" * 50)
print("ThreatDashboardDB")
print("=" * 50)

for collection_name in db.list_collection_names():
    collection = db[collection_name]
    count = collection.count_documents({})
    print(f"{collection_name}: {count} documents")