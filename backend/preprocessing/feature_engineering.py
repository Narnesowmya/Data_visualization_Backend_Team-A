"""Create the required security-event features and export the final dataset."""

import re
from pathlib import Path
import pandas as pd

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# File Paths
DATA_DIR = Path(__file__).resolve().parent

EVENTS_FILE = DATA_DIR / "security_events_cleaned_FINAL (1).csv"
THREAT_FEED_FILE = DATA_DIR / "threat_intelligence_cleaned.csv"
VULNERABILITY_FILE = DATA_DIR / "vulnerabilities_cleaned.csv"
OUTPUT_FILE = DATA_DIR / "feature_engineered_security_events.csv"


def build_features() -> pd.DataFrame:
    """Create all required feature engineering columns."""

    events = pd.read_csv(EVENTS_FILE)
    threat_feed = pd.read_csv(THREAT_FEED_FILE)
    if not VULNERABILITY_FILE.exists():
        raise FileNotFoundError(
            f"Required file missing: {VULNERABILITY_FILE.name}. "
            "CVSS Score enrichment cannot run without it."
        )
    vulnerabilities = pd.read_csv(VULNERABILITY_FILE)

    # Convert timestamp to datetime
    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        errors="raise"
    )

    # Clean string fields
    events["source_ip"] = (
        events["source_ip"]
        .astype(str)
        .str.strip()
    )

    threat_feed["indicator_value"] = (
        threat_feed["indicator_value"]
        .astype(str)
        .str.strip()
    )

    # 1. Hour Of Day
    events["hour_of_day"] = events["timestamp"].dt.hour

    # 2. Weekend Flag
    events["weekend_flag"] = (
        events["timestamp"].dt.dayofweek >= 5
    ).astype("int8")

    # 3. Severity Score
    severity_scores = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4,
    }

    events["severity_score"] = (
        events["severity"]
        .map(severity_scores)
        .astype("Int8")
    )

    # 4. Failed Login Count
    events["failed_login_count"] = (
        events.groupby("username")["failed_login_attempts"]
        .transform("sum")
    )

    # 5. Event Frequency
    events["event_frequency"] = (
        events.groupby("event_type")["event_type"]
        .transform("size")
    )

    # 6. Malicious IP Flag
    ip_threats = (
        threat_feed.loc[
            threat_feed["indicator_type"] == "IP Address"
        ]
        .copy()
        .drop_duplicates(subset="indicator_value")
    )

    malicious_ips = set(
        ip_threats["indicator_value"].dropna()
    )

    events["malicious_ip_flag"] = (
        events["source_ip"]
        .isin(malicious_ips)
        .astype("Int8")
    )

    # 7. Threat Feed Match
    ip_to_threat = (
        ip_threats
        .set_index("indicator_value")["threat_name"]
    )

    events["threat_feed_match"] = (
        events["source_ip"]
        .map(ip_to_threat)
        .fillna("No Match")
    )

    # --- Diagnostics: verify the IP join is actually comparable before we ---
    # --- trust a 0% match rate as a real finding rather than a join bug.  ---
    src_ips = set(events["source_ip"].dropna())
    dst_ips = set(events["destination_ip"].astype(str).str.strip().dropna())

    src_bad_format = [ip for ip in list(src_ips) if not IPV4_RE.match(ip)]
    feed_bad_format = [ip for ip in list(malicious_ips) if not IPV4_RE.match(ip)]

    overlap_source = src_ips & malicious_ips
    overlap_dest = dst_ips & malicious_ips

    print("\n--- Malicious IP match diagnostics ---")
    print(f"Threat feed IP indicators: {len(malicious_ips)}")
    print(f"Distinct event source_ip values: {len(src_ips)}")
    print(f"Sample source_ip values:  {list(src_ips)[:5]}")
    print(f"Sample threat feed IPs:   {list(malicious_ips)[:5]}")
    print(f"source_ip entries not in dotted-quad format:      {len(src_bad_format)}")
    print(f"threat feed entries not in dotted-quad format:    {len(feed_bad_format)}")
    print(f"Overlap (source_ip and threat feed):              {len(overlap_source)}")
    print(f"Overlap (destination_ip and threat feed):         {len(overlap_dest)}")
    if not overlap_source and not overlap_dest and not src_bad_format and not feed_bad_format:
        print(
            "Formats match on both sides and the overlap is still empty -- "
            "this looks like a genuine disjoint-data situation in the source "
            "files rather than a join bug, but it should be confirmed with "
            "whoever generated the synthetic data, since it makes "
            "malicious_ip_flag / threat_feed_match constant (always 0 / "
            "'No Match') and therefore carries no signal as a feature."
        )
    elif src_bad_format or feed_bad_format:
        print(
            "WARNING: format mismatch detected -- investigate before trusting "
            "the 0-match result."
        )

    # 8. CVSS Score Enrichment
    # vulnerabilities_cleaned.csv has TWO id columns (vulnerability_id and
    # cve_id). We don't assume which one events["vulnerability_id"] lines up
    # with -- we test both and use whichever gives a higher, and internally
    # consistent, match rate against events["vulnerability_id"].
    candidate_keys = [k for k in ("cve_id", "vulnerability_id") if k in vulnerabilities.columns]

    best_key = None
    best_match_count = -1
    match_report = {}
    for key in candidate_keys:
        lookup = vulnerabilities[[key, "cvss_score"]].dropna(subset=[key]).drop_duplicates(key)
        matched = events["vulnerability_id"].isin(set(lookup[key]))
        match_report[key] = int(matched.sum())
        if match_report[key] > best_match_count:
            best_match_count = match_report[key]
            best_key = key

    print("\n--- CVSS join-key diagnostics ---")
    for key, count in match_report.items():
        pct = 100 * count / len(events)
        print(f"Joining on vulnerabilities['{key}']: {count}/{len(events)} events matched ({pct:.1f}%)")
    print(f"Using join key: '{best_key}'")

    vuln_lookup = (
        vulnerabilities[[best_key, "cvss_score"]]
        .dropna(subset=[best_key])
        .drop_duplicates(best_key)
        .rename(columns={best_key: "_vuln_join_key", "cvss_score": "cvss_score_lookup"})
    )

    events = events.merge(
        vuln_lookup,
        left_on="vulnerability_id",
        right_on="_vuln_join_key",
        how="left",
    )

    # Authoritative score comes from the master vulnerability table when matched;
    # fall back to the pre-existing per-event value only when there's no match.
    lookup_score = pd.to_numeric(events["cvss_score_lookup"], errors="coerce")
    original_score = pd.to_numeric(events["cvss_score"], errors="coerce")
    matched_mask = lookup_score.notna()

    conflicts = (
        matched_mask
        & original_score.notna()
        & (lookup_score.round(2) != original_score.round(2))
    ).sum()
    match_rate = 100 * matched_mask.sum() / len(events)
    print(f"Rows where original cvss_score disagreed with the master lookup: {conflicts}")

    # Non-destructive: keep provenance instead of silently overwriting, since a
    # ~5% join rate with a ~99% disagreement rate on the rows that DO match is
    # weak enough evidence that "which score is right" is a data-ownership
    # question, not something to resolve unilaterally in code.
    events["cvss_score_source"] = matched_mask.map(
        {True: "master_vulnerability_table", False: "original_event_value"}
    )
    events["cvss_score"] = lookup_score.fillna(original_score)

    if match_rate < 25 and conflicts > 0.5 * matched_mask.sum():
        print(
            f"WARNING: only {match_rate:.1f}% of events matched a known CVE, and "
            f"{100 * conflicts / max(matched_mask.sum(), 1):.1f}% of those matches "
            "disagreed with the event's original score. This is weak evidence for "
            "a merge -- confirm with whoever owns vulnerabilities_cleaned.csv "
            "whether it's meant to be a comprehensive CVE reference before "
            "treating the enriched cvss_score as authoritative. The "
            "'cvss_score_source' column tags which rows were actually enriched "
            "vs. left on the original per-event value, so this can be filtered "
            "or reverted downstream without re-deriving it."
        )

    events.drop(columns=["_vuln_join_key", "cvss_score_lookup"], inplace=True)

    # Sanity check, split into two distinct questions:
    #   (1) Did the merge/dedup logic itself produce a conflict for any CVE
    #       that WAS matched to the master table? This should always be 0 --
    #       if it isn't, that's a real bug in the join.
    #   (2) Among UNMATCHED rows (no master-table score to fall back from),
    #       does the same vulnerability_id string ever carry different
    #       original per-event scores? This is expected and not a bug -- those
    #       rows were never touched by the join, they just reflect that the
    #       original per-event cvss_score wasn't consistent per-CVE to begin
    #       with. Reported separately so it isn't mistaken for a join failure.
    non_placeholder = events[events["vulnerability_id"] != "NO_CVE"].dropna(subset=["cvss_score"])
    matched_rows = non_placeholder[non_placeholder["cvss_score_source"] == "master_vulnerability_table"]
    unmatched_rows = non_placeholder[non_placeholder["cvss_score_source"] == "original_event_value"]

    real_conflicts = (matched_rows.groupby("vulnerability_id")["cvss_score"].nunique() > 1).sum()
    unmatched_variance = (unmatched_rows.groupby("vulnerability_id")["cvss_score"].nunique() > 1).sum()

    print(f"Genuine join conflicts among MATCHED CVEs (should be 0): {real_conflicts}")
    print(
        f"Unmatched CVE strings that happen to repeat with different original "
        f"scores (expected, not a bug, informational only): {unmatched_variance}"
    )

    # 9. Number Of Alerts Per User
    events["number_of_alerts_per_user"] = (
        events.groupby("username")["event_id"]
        .transform("size")
    )

    return events


def main() -> None:
    """Generate feature-engineered dataset."""

    features = build_features()

    features.to_csv(OUTPUT_FILE, index=False)

    required_features = [
        "failed_login_count",
        "hour_of_day",
        "weekend_flag",
        "severity_score",
        "event_frequency",
        "malicious_ip_flag",
        "threat_feed_match",
        "cvss_score",
        "cvss_score_source",
        "number_of_alerts_per_user",
    ]

    print("Feature engineering completed successfully.")
    print(f"Rows: {len(features):,}")
    print(f"Output File: {OUTPUT_FILE.name}")

    print("\nCreated Features:")
    for feature in required_features:
        status = "[OK]" if feature in features.columns else "[SKIPPED - source file missing]"
        print(f"{status} {feature}")

    present_features = [f for f in required_features if f in features.columns]
    print("\nMissing Values in Created Features:")
    print(features[present_features].isnull().sum())


if __name__ == "__main__":
    main()