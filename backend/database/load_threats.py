from load_data import load_csv_to_collection

print("Loading threats...")

load_csv_to_collection(
    "threat_intelligence_mitre_mapped.csv",
    "threats"
)

print("Finished loading threats.")