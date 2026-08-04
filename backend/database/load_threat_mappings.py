print("Loading threat mappings...")

from load_data import load_csv_to_collection

load_csv_to_collection(
    "threat_intelligence_mitre_mapped.csv",
    "threat_mappings"
)