"""
Milestone 3 - Task 6 & 7: Full Pipeline
==========================================
Consumes REAL data (does not modify any source file):
    - m2_threat_classification.csv   (Milestone 2 output: severity, prediction,
                                       threat_confidence_score, cvss_score)
    - task5_ioc_results.csv          (Task 5 final locked output)
    - m3_task1_inputs.csv            (Task 1 output: adds `asset_name` per event)
    - asset_criticality.csv          (Task 2 output, keyed by `asset_name`)

Produces:
    - risk_scores.csv     (Task 6 output, one row per event)
    - prioritized_incidents.csv  (Task 7 output, sorted, top N by risk)
    - risk_scores.json / prioritized_incidents.json (same data, JSON form)

IMPORTANT / OPEN ITEM (read before treating this as final):
    Event data (m3_task1_inputs.csv) references 6,327 unique asset_name
    values. asset_criticality.csv (the asset master / Task 2 output) only
    covers 450 of them. This is a real, confirmed coverage gap in the asset
    master data - not a formatting or join-key bug (both files use the same
    `asset_name` field, and matching names join correctly).

    Per team decision: we do NOT invent asset IDs or criticality values for
    the unmatched assets, since there is no evidence those event asset names
    correspond to assets that should exist in the master. Instead:
        - Events with a verified asset_name match  -> real criticality used,
          `asset_criticality_verified = True`
        - Events with no match in the asset master  -> criticality remains
          explicitly unknown/null, `asset_criticality_verified = False`.
          No Medium (0.5) value is fabricated.

    Risk Engine missing-component policy:
        The configured factor weights remain 0.25/0.25/0.20/0.20/0.10. When
        asset criticality is unknown, its 0.20 component is omitted for that
        event and the known weighted sum is divided by the available weight
        (0.80). The result is marked `risk_score_complete = False`, lists
        `asset_criticality` in `missing_components`, and reports
        `component_weight_coverage = 0.80`.

    Every output row carries `asset_criticality_verified` so downstream
    consumers (frontend, incident review, reporting) can immediately filter
    to only fully-verified risk scores, or clearly flag the unverified ones,
    rather than treating all 10,000 scores as equally trustworthy.

    Current coverage: only 482 / 10,000 events (4.8%) have verified asset
    criticality. This should be raised with whoever owns the asset master
    (Task 2) / event schema - it is a data completeness issue, not something
    Task 6 can or should resolve by fabricating records.
"""

import json
import pandas as pd

from risk_engine import calculate_risk
from prioritization import prioritize_incidents


UNVERIFIED_CRITICALITY_LABEL = "Unknown"


def load_and_merge(m2_path: str, ioc_path: str, task1_path: str, asset_path: str) -> pd.DataFrame:
    m2 = pd.read_csv(m2_path)
    ioc = pd.read_csv(ioc_path)
    task1 = pd.read_csv(task1_path)
    assets = pd.read_csv(asset_path)

    # Real join #1: M2 events <-> Task 5 IOC results, on event_id
    merged = m2.merge(
        ioc[["event_id", "ioc_status", "ioc_confidence", "ioc_type",
             "ioc_value", "threat_actor", "enrichment_source"]],
        on="event_id",
        how="left",
    )

    # Real join #2: bring in asset_name per event, from Task 1
    merged = merged.merge(
        task1[["event_id", "asset_name"]],
        on="event_id",
        how="left",
    )

    # Real join #3: asset_name -> asset master (Task 2), for verified criticality
    merged = merged.merge(
        assets[["asset_name", "criticality", "criticality_score"]],
        on="asset_name",
        how="left",
    )

    verified_mask = merged["criticality"].notna()
    merged["asset_criticality_verified"] = verified_mask

    # Verified rows keep the real label/score. Unverified rows are explicitly
    # Unknown with a null numeric score. The Risk Engine handles the missing
    # component; we never fabricate Medium (0.5).
    merged["asset_criticality"] = merged["criticality"].where(
        verified_mask, UNVERIFIED_CRITICALITY_LABEL
    )
    merged["asset_criticality_score_0to1"] = merged["criticality_score"].where(
        verified_mask, None
    )

    return merged


def score_all_events(merged_df: pd.DataFrame) -> list:
    results = []
    for _, row in merged_df.iterrows():
        event = {
            "event_id": row["event_id"],
            "severity": row.get("severity"),
            "ml_confidence": row.get("threat_confidence_score"),   # confirmed M2 source
            "ml_prediction": row.get("prediction"),                 # confirmed M2 source, carried through for reference
            "asset_criticality_score": (
                row.get("asset_criticality_score_0to1")
                if pd.notna(row.get("asset_criticality_score_0to1")) else None
            ),  # verified 0-1 value, otherwise null
            "cvss_score": row.get("cvss_score"),
            "ioc_status": row.get("ioc_status") if pd.notna(row.get("ioc_status")) else "No IOC Match",
            "ioc_confidence": row.get("ioc_confidence") if pd.notna(row.get("ioc_confidence")) else None,
            "failed_login_attempts": row.get("failed_login_attempts", 0) or 0,
            "after_hours": False,  # not present in current M2 schema; default until available
        }
        result = calculate_risk(event)

        # --- raw inputs, carried through so the output file is fully self-contained ---
        result["input_severity"] = event["severity"]
        result["input_ml_confidence_raw"] = event["ml_confidence"]        # 0-100, as received from M2
        result["input_ml_prediction"] = event["ml_prediction"]
        result["input_cvss_score"] = event["cvss_score"]                   # 0-10, as received
        result["input_ioc_status"] = event["ioc_status"]
        result["input_ioc_confidence"] = event["ioc_confidence"]
        result["input_asset_name"] = row.get("asset_name")
        result["input_asset_criticality_label"] = row.get("asset_criticality")
        result["input_asset_criticality_verified"] = bool(row.get("asset_criticality_verified"))
        result["input_asset_criticality_score_0to1"] = event["asset_criticality_score"]
        result["input_failed_login_attempts"] = event["failed_login_attempts"]

        # keep the old short-name columns too, for backward compatibility
        result["ml_prediction"] = event["ml_prediction"]
        result["ioc_status"] = event["ioc_status"]
        result["asset_name"] = row.get("asset_name")
        result["asset_criticality_label"] = row.get("asset_criticality")
        result["asset_criticality_verified"] = bool(row.get("asset_criticality_verified"))

        results.append(result)
    return results


def main():
    print("Loading and merging source data (read-only, no source files modified)...")
    merged = load_and_merge(
        "m2_threat_classification.csv",
        "task5_ioc_results.csv",
        "m3_task1_inputs.csv",
        "asset_criticality.csv",
    )
    verified_count = int(merged["asset_criticality_verified"].sum())
    print(f"  Merged {len(merged)} events (M2 x Task5 IOC x Task1 asset_name x Task2 asset master)")
    print(f"  Asset criticality VERIFIED for {verified_count} / {len(merged)} events "
          f"({verified_count/len(merged)*100:.1f}%)")
    print(f"  Remaining events keep asset criticality Unknown/null "
          f"(asset_criticality_verified=False); no Medium fallback is used")

    print("Scoring all events (Task 6)...")
    scored = score_all_events(merged)

    # ---- Outputs ----
    scored_df = pd.DataFrame(scored)

    # Task 6 deliverable: one file with full input + output per event
    input_cols = [c for c in scored_df.columns if c.startswith("input_")]
    output_cols = ["event_id", "risk_score_internal", "risk_score", "risk_level",
                   "priority", "risk_score_complete", "missing_components",
                   "component_weight_coverage", "asset_criticality_score",
                   "reasons", "calculated_at"]
    task6_cols = ["event_id"] + input_cols + [c for c in output_cols if c != "event_id"]
    task6_df = scored_df[task6_cols]
    task6_df.to_csv("Task6_Risk_Score_Input_Output.csv", index=False)
    with open("Task6_Risk_Score_Input_Output.json", "w") as f:
        json.dump(task6_df.to_dict(orient="records"), f, indent=2, default=str)

    with open("risk_scores.json", "w") as f:
        json.dump(scored, f, indent=2, default=str)
    scored_df.to_csv("risk_scores.csv", index=False)

    print("Prioritizing (Task 7)...")
    prioritized = prioritize_incidents(scored)
    prioritized_df = pd.DataFrame(prioritized)

    # Task 7 deliverable: input (the risk score result) + output (rank/order) per event
    prioritized_df.insert(0, "rank", range(1, len(prioritized_df) + 1))
    task7_cols = ["rank", "event_id", "risk_score", "risk_level", "priority",
                  "status", "reasons", "input_ioc_status", "input_asset_criticality_label",
                  "input_asset_criticality_verified"]
    task7_cols = [c for c in task7_cols if c in prioritized_df.columns]
    task7_df = prioritized_df[task7_cols]
    task7_df.to_csv("Task7_Prioritization_Input_Output.csv", index=False)
    with open("Task7_Prioritization_Input_Output.json", "w") as f:
        json.dump(task7_df.to_dict(orient="records"), f, indent=2, default=str)

    prioritized_df.to_csv("prioritized_incidents.csv", index=False)
    with open("prioritized_incidents.json", "w") as f:
        json.dump(prioritized, f, indent=2, default=str)

    # ---- Summary ----
    print("\n" + "=" * 55)
    print("TASK 6 / TASK 7 PIPELINE COMPLETE")
    print("=" * 55)
    print(f"Total events scored: {len(scored)}")
    print("\nRisk level distribution:")
    print(scored_df["risk_level"].value_counts().to_string())
    print("\nTop 10 highest-risk events:")
    print(prioritized_df[["event_id", "risk_score", "risk_level", "priority",
                           "ioc_status", "asset_criticality_verified"]].head(10).to_string(index=False))

    print("\nTop 10 highest-risk events with VERIFIED asset criticality only:")
    verified_only = prioritized_df[prioritized_df["asset_criticality_verified"] == True]
    print(verified_only[["event_id", "risk_score", "risk_level", "priority",
                          "asset_criticality_label"]].head(10).to_string(index=False))

    print("\nOutputs written:")
    print("  - risk_scores.csv / risk_scores.json           (Task 6, all events)")
    print("  - prioritized_incidents.csv / .json             (Task 7, sorted)")
    print("\nRemember: filter on `asset_criticality_verified == True` for any")
    print("output you present as fully evidence-based.")


if __name__ == "__main__":
    main()
