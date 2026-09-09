"""
Milestone 3 - Task 9: Response Recommendations Generator
=========================================================
Maps detected threats, MITRE ATT&CK techniques, and attack chain stages
to actionable SOC response recommendations.
"""

RECOMMENDATION_CATALOG = {
    "BRUTE_FORCE": [
        "Temporarily lock the affected account to prevent unauthorized access",
        "Investigate source IP address for malicious reputation and geolocation anomalies",
        "Review authentication logs across domain controllers for repeated failures",
        "Enforce Multi-Factor Authentication (MFA) on affected accounts"
    ],
    "MALWARE": [
        "Isolate affected endpoint/host from the network immediately",
        "Run an aggressive anti-malware and memory dump scan",
        "Investigate file hashes against threat intelligence databases",
        "Review active processes and kill suspicious child processes"
    ],
    "PRIVILEGE_ESCALATION": [
        "Revoke newly assigned local administrative and domain privileges",
        "Audit privilege escalation attempt logs and system audit trails",
        "Inspect sudoers, LSASS access, and token manipulation activity",
        "Reset credential cache for affected compromised identity"
    ],
    "LATERAL_MOVEMENT": [
        "Segment network zone around target asset to limit lateral spread",
        "Terminate active SSH, WinRM, and RDP sessions from source IP",
        "Audit pass-the-hash and Kerberos ticket request logs",
        "Rotate local admin passwords across all assets in the segment"
    ],
    "EXFILTRATION": [
        "Block suspicious destination IP/domain on perimeter firewall",
        "Inspect outbound proxy logs and data transfer volume",
        "Restrict DLP protocol channels and quarantine affected outbound traffic",
        "Escalate incident to SOC Level 2 analyst and Incident Response Lead"
    ],
    "DEFAULT": [
        "Investigate source IP and user credentials involved",
        "Review target asset telemetry and vulnerability exposure",
        "Monitor asset for recurring suspicious patterns over next 24 hours",
        "Escalate to SOC Tier 2 if additional anomalous behavior is detected"
    ]
}

TECHNIQUE_MAPPING = {
    "T1110": "BRUTE_FORCE",
    "T1078": "BRUTE_FORCE",
    "T1003": "PRIVILEGE_ESCALATION",
    "T1068": "PRIVILEGE_ESCALATION",
    "T1021": "LATERAL_MOVEMENT",
    "T1041": "EXFILTRATION",
    "T1048": "EXFILTRATION",
    "T1059": "MALWARE",
    "T1505.003": "MALWARE",
    "T1486": "MALWARE"
}

def get_recommendations_for_threat(threat_type: str, mitre_techniques: list = None) -> list:
    """
    Returns a prioritized list of actionable recommendations based on threat_type & MITRE techniques.
    """
    recommendations = []
    threat_upper = (threat_type or "").upper()

    if "BRUTE" in threat_upper or "LOGIN" in threat_upper or "CREDENTIAL" in threat_upper:
        recommendations.extend(RECOMMENDATION_CATALOG["BRUTE_FORCE"])
    elif "MALWARE" in threat_upper or "SHELL" in threat_upper or "RANSOMWARE" in threat_upper or "PROCESS" in threat_upper:
        recommendations.extend(RECOMMENDATION_CATALOG["MALWARE"])
    elif "PRIVILEGE" in threat_upper or "ESCALATION" in threat_upper:
        recommendations.extend(RECOMMENDATION_CATALOG["PRIVILEGE_ESCALATION"])
    elif "LATERAL" in threat_upper or "MOVEMENT" in threat_upper:
        recommendations.extend(RECOMMENDATION_CATALOG["LATERAL_MOVEMENT"])
    elif "EXFILTRATION" in threat_upper or "TRANSFER" in threat_upper or "DATA" in threat_upper:
        recommendations.extend(RECOMMENDATION_CATALOG["EXFILTRATION"])

    # Check MITRE techniques
    if mitre_techniques:
        for tech in mitre_techniques:
            cat = TECHNIQUE_MAPPING.get(str(tech).strip())
            if cat and cat in RECOMMENDATION_CATALOG:
                for rec in RECOMMENDATION_CATALOG[cat]:
                    if rec not in recommendations:
                        recommendations.append(rec)

    # Fallback if empty
    if not recommendations:
        recommendations = RECOMMENDATION_CATALOG["DEFAULT"].copy()

    return list(dict.fromkeys(recommendations))
