"""Milestone 3 - Task 9: Attack Chain Identification.

Uses MITRE tactics carried from the approved Task 4 context. No separate
hardcoded MITRE technique-ID mapping is maintained here. Task 7 risk values
are inherited unchanged.
"""
import pandas as pd

# Ordering follows the team's documented attack-chain sequence first, then
# other approved MITRE tactics so they can still be displayed when present.
STAGE_ORDER = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Credential Access": 5,
    "Discovery": 6,
    "Reconnaissance": 6.5,
    "Lateral Movement": 7,
    "Collection": 8,
    "Command And Control": 9,
    "Command and Control": 9,
    "Exfiltration": 10,
    "Impact": 11,
    "Defense Evasion": 12,
    "Defense Impairment": 12,
    "Stealth": 13,
}


def _split(v):
    return [] if pd.isna(v) or not str(v) else [x for x in str(v).split("|") if x]


def build_attack_chains(correlations, prioritized):
    p = prioritized.copy()
    p["event_id"] = p["event_id"].astype(str)
    pmap = p.set_index("event_id").to_dict("index")
    rows = []

    for _, c in correlations.iterrows():
        ids = _split(c["event_ids"])
        tactics = _split(c.get("mitre_tactics", ""))
        techniques = _split(c.get("mitre_techniques", ""))
        stages = sorted(set(tactics), key=lambda s: STAGE_ORDER.get(s, 99))

        # An attack chain needs evidence from at least two distinct approved
        # MITRE tactics/stages, not merely multiple events of one type.
        if len(stages) < 2:
            continue

        scores = []
        for eid in ids:
            rec = pmap.get(eid, {})
            if pd.notna(rec.get("risk_score")):
                scores.append(float(rec["risk_score"]))
        risk = max(scores) if scores else None

        level = "Unknown"
        if risk is not None:
            for eid in ids:
                rec = pmap.get(eid, {})
                if pd.notna(rec.get("risk_score")) and float(rec["risk_score"]) == risk:
                    level = rec.get("risk_level") or "Unknown"
                    break

        confidence = min(99, 60 + 8 * len(ids))
        rows.append({
            "attack_chain_id": f"AC-{len(rows) + 1:05d}",
            "correlation_id": c["correlation_id"],
            "event_ids": c["event_ids"],
            "event_count": int(c["event_count"]),
            "correlation_rule": c["rule"],
            "mitre_techniques": "|".join(techniques),
            "mitre_tactics": "|".join(stages),
            "attack_stages": " → ".join(stages),
            "risk_score": risk,
            "risk_level": level,
            "confidence": confidence,
            "start_time": c["start_time"],
            "end_time": c["end_time"],
            "window_minutes": c.get("window_minutes"),
            "asset_name": c["asset_name"],
            "source_ip": c["source_ip"],
        })
    return pd.DataFrame(rows)


def main(correlation_csv="correlations.csv", prioritized_csv="prioritized_incidents.csv", output_csv="attack_chains.csv"):
    out = build_attack_chains(pd.read_csv(correlation_csv), pd.read_csv(prioritized_csv))
    out.to_csv(output_csv, index=False)
    return out


if __name__ == "__main__":
    main()
