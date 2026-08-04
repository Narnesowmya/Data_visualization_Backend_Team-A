print("Loading processed logs...")

from load_data import load_csv_to_collection

load_csv_to_collection(
    "security_events_normalized.csv",
    "processed_logs"
)