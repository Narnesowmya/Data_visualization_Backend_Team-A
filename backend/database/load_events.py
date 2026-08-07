from load_data import load_csv_to_collection

print("Loading events...")

load_csv_to_collection(
    "security_events_normalized.csv",
    "events"
)

print("Finished loading events.")