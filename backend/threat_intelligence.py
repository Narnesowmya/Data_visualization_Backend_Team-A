import os
import pandas as pd


# M3 Task 5 - Threat Intelligence / IOC Enrichment

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EVENT_FILE = os.path.join(
    BASE_DIR, "data", "security_events_cleaned.csv"
)

IOC_FILE = os.path.join(
    BASE_DIR, "data", "threat_intelligence_cleaned.csv"
)

SYNTHETIC_MAPPING_FILE = os.path.join(
    BASE_DIR, "data", "m3_synthetic_ioc_mapping.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR, "data", "task5_ioc_results.csv"
)


def normalize(value):
    """Normalize values for comparison."""
    if pd.isna(value):
        return ""
    return str(value).strip().lower()


def confidence_to_status(confidence):
    """
    Convert IOC confidence to Task 5 status.

    High -> Malicious
    Medium -> Suspicious
    Low -> Suspicious
    """

    confidence = normalize(confidence)

    if confidence == "high":
        return "Malicious"

    if confidence in {"medium", "low"}:
        return "Suspicious"

    return "No IOC Match"


print("MILESTONE 3 - TASK 5")
print("THREAT INTELLIGENCE / IOC ENRICHMENT")
print()

# Load M2 security events
print("[1] Loading M2 security events...")

events = pd.read_csv(EVENT_FILE)

print(f"Event records loaded: {len(events)}")
print("Event columns:")
print(events.columns.tolist())
print()


# Load M2 threat intelligence
print("[2] Loading M2 threat intelligence IOC dataset...")

ioc = pd.read_csv(IOC_FILE)

print(f"IOC records loaded: {len(ioc)}")
print("IOC columns:")
print(ioc.columns.tolist())
print()


# Validate required columns
print("[3] Validating required columns...")

required_event_columns = {
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "event_type",
}

required_ioc_columns = {
    "indicator_id",
    "indicator_type",
    "indicator_value",
    "threat_name",
    "threat_actor",
    "confidence",
    "severity",
}

missing_event_columns = (
    required_event_columns - set(events.columns)
)

missing_ioc_columns = (
    required_ioc_columns - set(ioc.columns)
)

if missing_event_columns:
    raise ValueError(
        f"Missing event columns: {sorted(missing_event_columns)}"
    )

if missing_ioc_columns:
    raise ValueError(
        f"Missing IOC columns: {sorted(missing_ioc_columns)}"
    )

print("Required columns validated successfully.")
print()


# Show IOC indicator types
print("[4] IOC indicator types:")

print(ioc["indicator_type"].value_counts())
print()


# Prepare IP IOC lookup
print("[5] Preparing genuine IP IOC lookup...")

ip_iocs = ioc[
    ioc["indicator_type"]
    .astype(str)
    .str.strip()
    .str.lower()
    .eq("ip address")
].copy()

ip_iocs["normalized_indicator_value"] = (
    ip_iocs["indicator_value"].map(normalize)
)

ip_iocs = ip_iocs[
    ip_iocs["normalized_indicator_value"] != ""
]

ip_lookup = (
    ip_iocs
    .drop_duplicates("normalized_indicator_value")
    .set_index("normalized_indicator_value")
)

print(f"IP IOC records: {len(ip_iocs)}")
print(
    "Unique IP IOC lookup values:",
    ip_iocs["normalized_indicator_value"].nunique()
)
print()


# Validate genuine IOC overlap
print("[6] Genuine IOC overlap validation")

event_source_ips = set(
    events["source_ip"].map(normalize)
)

event_destination_ips = set(
    events["destination_ip"].map(normalize)
)

ioc_ips = set(
    ip_iocs["normalized_indicator_value"]
)

event_source_ips.discard("")
event_destination_ips.discard("")

source_matches = event_source_ips & ioc_ips
destination_matches = event_destination_ips & ioc_ips
all_ip_matches = source_matches | destination_matches

print(
    f"Unique event source IPs: {len(event_source_ips)}"
)

print(
    f"Unique event destination IPs: "
    f"{len(event_destination_ips)}"
)

print(
    f"Unique IOC IPs: {len(ioc_ips)}"
)

print(
    f"Source IP matches: {len(source_matches)}"
)

print(
    f"Destination IP matches: {len(destination_matches)}"
)

print(
    f"Total unique IP matches: {len(all_ip_matches)}"
)

if all_ip_matches:
    print("\nGenuine matching IPs:")
    for ip in sorted(all_ip_matches):
        print(ip)
else:
    print("\nNo genuine IP IOC overlap found.")

print()


# Load approved synthetic/demo mappings
print("[7] Loading approved synthetic/demo mappings...")

if not os.path.exists(SYNTHETIC_MAPPING_FILE):
    raise FileNotFoundError(
        "Synthetic mapping file not found:\n"
        f"{SYNTHETIC_MAPPING_FILE}"
    )

synthetic = pd.read_csv(SYNTHETIC_MAPPING_FILE)

required_mapping_columns = {
    "event_id",
    "indicator_id",
    "reason",
}

missing_mapping_columns = (
    required_mapping_columns - set(synthetic.columns)
)

if missing_mapping_columns:
    raise ValueError(
        "Missing synthetic mapping columns: "
        f"{sorted(missing_mapping_columns)}"
    )

print(f"Synthetic mappings loaded: {len(synthetic)}")
print("\nSynthetic mapping:")
print(synthetic.to_string(index=False))
print()


# Validate synthetic mappings
print("[8] Validating synthetic mappings...")

valid_event_ids = set(
    events["event_id"].astype(str)
)

valid_indicator_ids = set(
    ioc["indicator_id"].astype(str)
)

mapping_event_ids = set(
    synthetic["event_id"].astype(str)
)

mapping_indicator_ids = set(
    synthetic["indicator_id"].astype(str)
)

invalid_event_ids = (
    mapping_event_ids - valid_event_ids
)

invalid_indicator_ids = (
    mapping_indicator_ids - valid_indicator_ids
)

if invalid_event_ids:
    raise ValueError(
        "Synthetic mapping contains unknown event IDs: "
        f"{sorted(invalid_event_ids)}"
    )

if invalid_indicator_ids:
    raise ValueError(
        "Synthetic mapping contains unknown IOC IDs: "
        f"{sorted(invalid_indicator_ids)}"
    )

if synthetic["event_id"].duplicated().any():
    raise ValueError(
        "Synthetic mapping contains duplicate event IDs."
    )

print("Synthetic mappings validated successfully.")
print()


# Create lookups
ioc_records = (
    ioc
    .set_index("indicator_id")
    .to_dict("index")
)

synthetic_lookup = (
    synthetic
    .set_index("event_id")
    .to_dict("index")
)


# Create output
print("[9] Creating Task 5 output...")

output_columns = [
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "event_type",
    "ioc_status",
    "ioc_type",
    "ioc_value",
    "threat_name",
    "threat_actor",
    "ioc_confidence",
    "ioc_severity",
    "indicator_id",
    "matched_from",
    "enrichment_source",
]

results = []


# Process events
for _, event in events.iterrows():

    event_id = str(event["event_id"])

    source_ip = normalize(event["source_ip"])
    destination_ip = normalize(event["destination_ip"])

    result = {
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "source_ip": event["source_ip"],
        "destination_ip": event["destination_ip"],
        "event_type": event["event_type"],
        "ioc_status": "No IOC Match",
        "ioc_type": None,
        "ioc_value": None,
        "threat_name": None,
        "threat_actor": None,
        "ioc_confidence": None,
        "ioc_severity": None,
        "indicator_id": None,
        "matched_from": None,
        "enrichment_source": "No Match",
    }

    # Genuine source IP match
    if source_ip and source_ip in ip_lookup.index:

        matched_ioc = ip_lookup.loc[source_ip]

        result.update({
            "ioc_status": confidence_to_status(
                matched_ioc["confidence"]
            ),
            "ioc_type": matched_ioc["indicator_type"],
            "ioc_value": matched_ioc["indicator_value"],
            "threat_name": matched_ioc["threat_name"],
            "threat_actor": matched_ioc["threat_actor"],
            "ioc_confidence": matched_ioc["confidence"],
            "ioc_severity": matched_ioc["severity"],
            "indicator_id": matched_ioc["indicator_id"],
            "matched_from": "source_ip",
            "enrichment_source": "Real IOC Match",
        })

    # Genuine destination IP match
    elif (
        destination_ip
        and destination_ip in ip_lookup.index
    ):

        matched_ioc = ip_lookup.loc[destination_ip]

        result.update({
            "ioc_status": confidence_to_status(
                matched_ioc["confidence"]
            ),
            "ioc_type": matched_ioc["indicator_type"],
            "ioc_value": matched_ioc["indicator_value"],
            "threat_name": matched_ioc["threat_name"],
            "threat_actor": matched_ioc["threat_actor"],
            "ioc_confidence": matched_ioc["confidence"],
            "ioc_severity": matched_ioc["severity"],
            "indicator_id": matched_ioc["indicator_id"],
            "matched_from": "destination_ip",
            "enrichment_source": "Real IOC Match",
        })

    # Approved synthetic/demo match
    elif event_id in synthetic_lookup:

        mapping = synthetic_lookup[event_id]

        indicator_id = str(
            mapping["indicator_id"]
        )

        matched_ioc = ioc_records[indicator_id]

        result.update({
            "ioc_status": confidence_to_status(
                matched_ioc["confidence"]
            ),
            "ioc_type": matched_ioc["indicator_type"],
            "ioc_value": matched_ioc["indicator_value"],
            "threat_name": matched_ioc["threat_name"],
            "threat_actor": matched_ioc["threat_actor"],
            "ioc_confidence": matched_ioc["confidence"],
            "ioc_severity": matched_ioc["severity"],
            "indicator_id": indicator_id,
            "matched_from": "synthetic_mapping",
            "enrichment_source": "Synthetic Demo",
        })

    results.append(result)


# Create output dataframe
output = pd.DataFrame(
    results,
    columns=output_columns
)


# Validate output
print("[10] Validating output...")

if len(output) != len(events):
    raise ValueError(
        "Output row count does not match event row count."
    )

missing_output_columns = (
    set(output_columns) - set(output.columns)
)

if missing_output_columns:
    raise ValueError(
        f"Missing output columns: {sorted(missing_output_columns)}"
    )

allowed_statuses = {
    "Malicious",
    "Suspicious",
    "No IOC Match",
}

invalid_statuses = (
    set(output["ioc_status"].dropna())
    - allowed_statuses
)

if invalid_statuses:
    raise ValueError(
        f"Unexpected IOC statuses: {sorted(invalid_statuses)}"
    )

print("Output validation successful.")
print()


# Summary
real_matches = (
    output["enrichment_source"]
    == "Real IOC Match"
).sum()

synthetic_matches = (
    output["enrichment_source"]
    == "Synthetic Demo"
).sum()

no_matches = (
    output["ioc_status"]
    == "No IOC Match"
).sum()

source_real_matches = (
    (output["enrichment_source"] == "Real IOC Match")
    &
    (output["matched_from"] == "source_ip")
).sum()

destination_real_matches = (
    (output["enrichment_source"] == "Real IOC Match")
    &
    (output["matched_from"] == "destination_ip")
).sum()


print("TASK 5 SUMMARY")
print("-" * 40)

print(
    f"Event records processed: {len(events)}"
)

print(
    f"IOC records processed: {len(ioc)}"
)

print(
    f"IP IOC records: {len(ip_iocs)}"
)

print(
    f"\nGenuine source IP matches: "
    f"{source_real_matches}"
)

print(
    f"Genuine destination IP matches: "
    f"{destination_real_matches}"
)

print(
    f"Genuine IOC matches: {real_matches}"
)

print(
    f"\nSynthetic/demo IOC matches: "
    f"{synthetic_matches}"
)

print(
    f"No IOC Match events: {no_matches}"
)

print("\nIOC status summary:")
print(
    output["ioc_status"]
    .value_counts(dropna=False)
)

print("\nEnrichment source summary:")
print(
    output["enrichment_source"]
    .value_counts(dropna=False)
)


# Show synthetic records
print("\nSynthetic/demo enriched records:")

demo_output = output[
    output["enrichment_source"] == "Synthetic Demo"
][
    [
        "event_id",
        "event_type",
        "ioc_status",
        "ioc_type",
        "ioc_value",
        "threat_name",
        "threat_actor",
        "ioc_confidence",
        "ioc_severity",
        "enrichment_source",
    ]
]

if len(demo_output):
    print(demo_output.to_string(index=False))
else:
    print("No synthetic/demo records found.")


# Show unmatched sample
print("\nSample No IOC Match records:")

no_match_output = output[
    output["ioc_status"] == "No IOC Match"
].head(5)

print(
    no_match_output[
        [
            "event_id",
            "event_type",
            "ioc_status",
            "ioc_type",
            "ioc_value",
            "threat_name",
            "threat_actor",
            "ioc_confidence",
            "ioc_severity",
            "enrichment_source",
        ]
    ].to_string(index=False)
)


# Risk Engine handoff fields
risk_engine_fields = [
    "event_id",
    "ioc_status",
    "ioc_confidence",
    "ioc_type",
    "ioc_value",
    "source_ip",
    "destination_ip",
]

print("\nRisk Engine handoff fields:")
print(risk_engine_fields)


# Save output
print("\n[11] Saving Task 5 output...")

output.to_csv(
    OUTPUT_FILE,
    index=False
)

print(
    f"Output saved to:\n{OUTPUT_FILE}"
)

print("\nTASK 5 COMPLETED")