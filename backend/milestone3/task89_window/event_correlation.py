"""Milestone 3 - Task 8: Event Correlation.

Correlation is constrained by a short time window. For the supplied dataset,
the primary available key is asset_name, so same-asset events are correlated
only when consecutive events are no more than TIME_WINDOW_MINUTES apart.
MITRE context is loaded from the approved Task 4 mapping file rather than a
second hardcoded technique map.
"""
from pathlib import Path
import pandas as pd

TIME_WINDOW_MINUTES = 30
SUSPICIOUS_TYPES = {
    "Failed Login", "Brute Force", "Unauthorized Access", "Port Scan",
    "Credential Dumping", "Suspicious Process Execution", "Web Shell Detected",
    "Privilege Escalation", "Lateral Movement Detected", "Data Exfiltration Attempt",
    "DNS Tunneling Detected", "Malware Detection", "Ransomware Detected",
    "SQL Injection Attempt", "Session Hijacking Attempt", "DDoS Attempt",
    "Phishing Email", "Firewall Rule Change"
}


def load_mitre_context(path):
    """Load the approved Task 4 MITRE context and keep only useful columns."""
    context = pd.read_csv(path)
    required = {"event_type", "mitre_id", "technique_name", "tactic"}
    missing = required - set(context.columns)
    if missing:
        raise ValueError(f"Task 4 MITRE context missing columns: {sorted(missing)}")
    context = context.dropna(subset=["event_type", "mitre_id"]).copy()
    return context.drop_duplicates(subset=["event_type", "mitre_id", "technique_name", "tactic"])


def _context_maps(context):
    technique_map = context.groupby("event_type")["mitre_id"].apply(
        lambda s: "|".join(sorted(set(s.astype(str))))
    ).to_dict()
    tactic_map = context.groupby("event_type")["tactic"].apply(
        lambda s: "|".join(sorted(set(str(x) for x in s.dropna())))
    ).to_dict()
    return technique_map, tactic_map


def load_events(path, mitre_context_path):
    df = pd.read_csv(path)
    if "timestamp" not in df.columns:
        raise ValueError("Input events must contain timestamp")
    if "asset_name" not in df.columns:
        raise ValueError("Input events must contain asset_name")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    context = load_mitre_context(mitre_context_path)
    technique_map, tactic_map = _context_maps(context)
    df["mitre_techniques"] = df["event_type"].map(technique_map).fillna("")
    df["mitre_tactics"] = df["event_type"].map(tactic_map).fillna("")
    return df


def _make_corr(rule, group):
    group = group.sort_values("timestamp")
    return {
        "rule": rule,
        "event_ids": "|".join(group["event_id"].astype(str)),
        "asset_name": str(group.iloc[0].get("asset_name", "")),
        "source_ip": "|".join(sorted(set(group["source_ip"].dropna().astype(str)))) if "source_ip" in group else "",
        "event_types": "|".join(group["event_type"].astype(str)),
        "mitre_techniques": "|".join(sorted(set(
            tech for value in group["mitre_techniques"] for tech in str(value).split("|") if tech
        ))),
        "mitre_tactics": "|".join(sorted(set(
            tactic for value in group["mitre_tactics"] for tactic in str(value).split("|") if tactic
        ))),
        "start_time": str(group.iloc[0]["timestamp"]),
        "end_time": str(group.iloc[-1]["timestamp"]),
        "window_minutes": round((group.iloc[-1]["timestamp"] - group.iloc[0]["timestamp"]).total_seconds() / 60, 2),
        "event_count": int(len(group)),
    }


def _window_groups(g, window_minutes=TIME_WINDOW_MINUTES):
    """Split a sorted group whenever the next event is beyond the short window."""
    g = g.sort_values("timestamp")
    groups = []
    current = []
    previous = None
    limit = window_minutes * 60
    for _, row in g.iterrows():
        if previous is None or (row["timestamp"] - previous).total_seconds() <= limit:
            current.append(row)
        else:
            if len(current) >= 2:
                groups.append(pd.DataFrame(current))
            current = [row]
        previous = row["timestamp"]
    if len(current) >= 2:
        groups.append(pd.DataFrame(current))
    return groups


def correlate_events(events, window_minutes=TIME_WINDOW_MINUTES):
    """Return correlations only when related events are within the time window."""
    rows = []

    # Primary rule: same asset + short time window.
    for _, g in events.dropna(subset=["asset_name", "timestamp"]).groupby("asset_name"):
        for window_group in _window_groups(g, window_minutes):
            rows.append(_make_corr("asset_time_window", window_group))

    # Optional user rule when an integrated upstream dataset provides user_id.
    if "user_id" in events.columns:
        work = events.dropna(subset=["user_id", "timestamp"])
        for _, g in work.groupby("user_id"):
            for window_group in _window_groups(g, window_minutes):
                rows.append(_make_corr("user_time_window", window_group))

    # Optional repeated source-IP rule, also constrained by the same window.
    if "source_ip" in events.columns:
        work = events[events["event_type"].isin(SUSPICIOUS_TYPES)].dropna(subset=["source_ip", "timestamp"])
        for _, g in work.groupby("source_ip"):
            for window_group in _window_groups(g, window_minutes):
                rows.append(_make_corr("source_ip_time_window", window_group))

    columns = ["correlation_id", "rule", "event_ids", "asset_name", "source_ip",
               "event_types", "mitre_techniques", "mitre_tactics", "start_time",
               "end_time", "window_minutes", "event_count"]
    if not rows:
        return pd.DataFrame(columns=columns)
    out = pd.DataFrame(rows).drop_duplicates(subset=["rule", "event_ids"])
    out.insert(0, "correlation_id", [f"CORR-{i:05d}" for i in range(1, len(out) + 1)])
    return out[columns]


def main(input_csv="m3_task1_inputs.csv", output_csv="correlations.csv", mitre_context_csv="task4_mitre_context.csv"):
    out = correlate_events(load_events(Path(input_csv), Path(mitre_context_csv)))
    out.to_csv(output_csv, index=False)
    return out


if __name__ == "__main__":
    main()
