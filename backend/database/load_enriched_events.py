print("Loading enriched events...")

from load_data import load_csv_to_collection

load_csv_to_collection(
    "security_events_enriched.csv",
    "enriched_events"
)