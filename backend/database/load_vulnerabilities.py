from load_data import load_csv_to_collection

print("Loading vulnerabilities...")

load_csv_to_collection(
    "vulnerabilities_cleaned.csv",
    "vulnerabilities"
)
