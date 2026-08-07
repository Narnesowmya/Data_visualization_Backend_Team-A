import os
import pandas as pd
from mongo_connection import db

def load_csv_to_collection(csv_filename, collection_name):
    # Get the backend folder
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Build the full path
    csv_path = os.path.join(base_dir, "data", csv_filename)

    print(f"Reading file: {csv_path}")

    df = pd.read_csv(csv_path)

    print(f"Rows found: {len(df)}")

    collection = db[collection_name]

    # Clear existing documents
    collection.delete_many({})

    # Insert new documents
    result = collection.insert_many(df.to_dict("records"))

    print(f"✅ Inserted {len(result.inserted_ids)} records into '{collection_name}'")