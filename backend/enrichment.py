

import pandas as pd
import numpy as np
import random

random.seed(42)
np.random.seed(42)

security = pd.read_csv("security_events.csv")
assets = pd.read_csv("asset.csv")
vulnerabilities = pd.read_csv("vulnerability.csv")
threat = pd.read_csv("threat_intelligence.csv")
incidents = pd.read_csv("incident_history.csv")
mitre = pd.read_csv("mitre_attack.csv")


security["login_hour"] = pd.to_datetime(
    security["timestamp"]
).dt.hour

security["is_business_hours"] = np.where(
    security["login_hour"].between(9,18),
    "Yes",
    "No"
)

security["network_zone"] = np.random.choice(
    ["Internal","DMZ","External"],
    len(security)
)

security["risk_score"] = np.random.randint(
    20,
    100,
    len(security)
)

security["event_category"] = np.random.choice(
    [
        "Authentication",
        "Malware",
        "Network",
        "Privilege Escalation",
        "Reconnaissance"
    ],
    len(security)
)

security["is_weekend"] = np.where(
    pd.to_datetime(security["timestamp"]).dt.dayofweek>=5,
    "Yes",
    "No"
)

assets["asset_value"] = np.random.choice(
    ["Low","Medium","High","Critical"],
    len(assets)
)

assets["internet_facing"] = np.random.choice(
    ["Yes","No"],
    len(assets)
)

assets["business_unit"] = np.random.choice(
    [
        "Finance",
        "IT",
        "HR",
        "Sales",
        "Operations"
    ],
    len(assets)
)

assets["criticality_score"] = np.random.randint(
    40,
    100,
    len(assets)
)

assets["compliance"] = np.random.choice(
    [
        "ISO27001",
        "PCI-DSS",
        "GDPR",
        "HIPAA"
    ],
    len(assets)
)


vulnerabilities["epss_score"] = np.round(
    np.random.uniform(0,1,len(vulnerabilities)),
    3
)

vulnerabilities["exploit_available"] = np.random.choice(
    ["Yes","No"],
    len(vulnerabilities)
)

vulnerabilities["patch_priority"] = np.random.choice(
    [
        "Low",
        "Medium",
        "High",
        "Critical"
    ],
    len(vulnerabilities)
)

vulnerabilities["days_since_patch"] = np.random.randint(
    0,
    365,
    len(vulnerabilities)
)


threat["malware_family"] = np.random.choice(
    [
        "Emotet",
        "TrickBot",
        "QakBot",
        "AgentTesla",
        "CobaltStrike"
    ],
    len(threat)
)

threat["ioc_reputation"] = np.random.choice(
    [
        "Benign",
        "Suspicious",
        "Malicious"
    ],
    len(threat)
)

threat["threat_actor"] = np.random.choice(
    [
        "APT28",
        "APT29",
        "Lazarus",
        "FIN7",
        "Unknown"
    ],
    len(threat)
)

threat["confidence_score"] = np.random.randint(
    50,
    100,
    len(threat)
)


incidents["sla_status"] = np.random.choice(
    [
        "Met",
        "Breached"
    ],
    len(incidents)
)

incidents["downtime_minutes"] = np.random.randint(
    5,
    500,
    len(incidents)
)

incidents["financial_impact"] = np.random.randint(
    1000,
    100000,
    len(incidents)
)

incidents["root_cause"] = np.random.choice(
    [
        "Phishing",
        "Weak Password",
        "Malware",
        "Misconfiguration",
        "Insider Threat"
    ],
    len(incidents)
)


mitre["tactic"] = np.random.choice(
    [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Credential Access",
        "Defense Evasion",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Exfiltration"
    ],
    len(mitre)
)

mitre["detection_maturity"] = np.random.choice(
    [
        "Low",
        "Medium",
        "High"
    ],
    len(mitre)
)

mitre["mitigation_priority"] = np.random.choice(
    [
        "Low",
        "Medium",
        "High",
        "Critical"
    ],
    len(mitre)
)


security.to_csv("security_events_enriched.csv", index=False)
assets.to_csv("assets_enriched.csv", index=False)
vulnerabilities.to_csv("vulnerabilities_enriched.csv", index=False)
threat.to_csv("threat_intelligence_enriched.csv", index=False)
incidents.to_csv("incident_history_enriched.csv", index=False)
mitre.to_csv("mitre_attack_enriched.csv", index=False)

print("===================================")
print("DATA ENRICHMENT COMPLETED")
print("All enriched CSV files saved.")
print("===================================")