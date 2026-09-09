"""
Milestone 3 - Task 10: Incident Creation & Database Ingestion Script (Cleaned & Finalized)
==========================================================================================
Packages output data from Task 1-9 into structured SOC Incident records and
persists them into the MongoDB `incidents` collection (and `data/incidents.json` fallback).

Cleaned to:
1. Consume Task 9 attack_stages / event sequences directly for genuine attack chain incidents.
2. Set attack_chain = [] for correlations without a Task 9 attack chain (mitre_techniques and tactics remain supporting intelligence).
3. Zero fabricated values for asset, IP, user, risk, or explainability.
"""
import os
import json
import logging
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

# Adjust python path if executed directly
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from risk.risk_score import calculate_risk, classify_risk
from risk.recommendations import get_recommendations_for_threat
from database.incident_repository import save_incidents_batch
from database.m3_mongodb import is_mongodb_available, get_database

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("import_incidents")


def load_prioritized_events() -> dict:
    events_map = {}
    path = settings.RISK_SCORES_JSON
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data:
                events_map[item["event_id"]] = item
    elif os.path.exists(settings.PRIORITIZED_INCIDENTS_CSV):
        df = pd.read_csv(settings.PRIORITIZED_INCIDENTS_CSV)
        for _, row in df.iterrows():
            events_map[row["event_id"]] = row.to_dict()

    # Join source_ip from Task 1 raw inputs if present
    task1_path = settings.DATA_DIR / "m3_task1_inputs.csv"
    if os.path.exists(task1_path):
        df_t1 = pd.read_csv(task1_path)
        if "event_id" in df_t1.columns and "source_ip" in df_t1.columns:
            ip_map = dict(zip(df_t1["event_id"], df_t1["source_ip"]))
            for eid, evt in events_map.items():
                if eid in ip_map and pd.notna(ip_map[eid]):
                    evt["source_ip"] = str(ip_map[eid])
    return events_map



def load_correlations() -> list:
    if os.path.exists(settings.CORRELATIONS_JSON):
        with open(settings.CORRELATIONS_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    elif os.path.exists(settings.DATA_DIR / "correlations.csv"):
        df = pd.read_csv(settings.DATA_DIR / "correlations.csv")
        return df.to_dict(orient="records")
    return []


def load_attack_chains() -> list:
    if os.path.exists(settings.ATTACK_CHAINS_JSON):
        with open(settings.ATTACK_CHAINS_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    elif os.path.exists(settings.DATA_DIR / "attack_chains.csv"):
        df = pd.read_csv(settings.DATA_DIR / "attack_chains.csv")
        return df.to_dict(orient="records")
    return []


def get_event_explainability(evt: dict) -> Optional[dict]:
    if "explainability" in evt and isinstance(evt["explainability"], dict):
        return evt["explainability"]
    
    # Generate genuine explainability from event fields using approved Task 6/7 engine
    raw_event = {
        "event_id": evt.get("event_id"),
        "severity": evt.get("input_severity") or evt.get("severity"),
        "ml_confidence": evt.get("input_ml_confidence_raw") or evt.get("ml_confidence"),
        "asset_criticality": evt.get("input_asset_criticality_label") or evt.get("asset_criticality_label") or evt.get("asset_criticality"),
        "asset_criticality_score": evt.get("input_asset_criticality_score_0to1") or evt.get("asset_criticality_score"),
        "cvss_score": evt.get("input_cvss_score") or evt.get("cvss_score"),
        "ioc_status": evt.get("input_ioc_status") or evt.get("ioc_status"),
        "ioc_confidence": evt.get("input_ioc_confidence") or evt.get("ioc_confidence"),
        "failed_login_attempts": evt.get("input_failed_login_attempts", 0) or 0
    }
    calc = calculate_risk(raw_event)
    return calc.get("explainability")


def build_incidents() -> list:
    logger.info("Loading Task 1-9 outputs for incident construction...")
    events_map = load_prioritized_events()
    correlations = load_correlations()
    attack_chains = load_attack_chains()

    # Index Task 9 attack chains by correlation_id
    chain_map = {chain.get("correlation_id"): chain for chain in attack_chains if chain.get("correlation_id")}

    incidents = []
    seen_event_ids = set()
    inc_counter = 1

    # 1. Process Correlated Groups into Incidents
    for corr in correlations:
        corr_id = corr.get("correlation_id", f"CORR-{inc_counter:05d}")
        evt_ids_str = corr.get("event_ids", "")
        evt_ids = [e.strip() for e in str(evt_ids_str).split("|") if e.strip()]
        if not evt_ids:
            continue

        seen_event_ids.update(evt_ids)
        asset_id = corr.get("asset_name") or corr.get("asset_id") or None
        
        source_ip_raw = corr.get("source_ip")
        source_ip = str(source_ip_raw).split("|")[0].strip() if source_ip_raw and str(source_ip_raw).strip() else None

        # Fetch associated prioritized event records
        corr_events = [events_map[eid] for eid in evt_ids if eid in events_map]

        # User ID from genuine event data
        affected_user = None
        for evt in corr_events:
            u = evt.get("user_id") or evt.get("affected_user") or evt.get("input_user_id")
            if u and str(u).strip() and str(u).lower() != "nan":
                affected_user = str(u).strip()
                break

        # Max risk score from correlated events
        if corr_events:
            max_event = max(corr_events, key=lambda x: float(x.get("risk_score", 0)))
            risk_score = float(max_event.get("risk_score", 0.0))
            explainability = get_event_explainability(max_event)
        else:
            risk_score = 0.0
            explainability = None

        mitre_raw = corr.get("mitre_techniques", "")
        mitre_list = [m.strip() for m in str(mitre_raw).split("|") if m.strip()] if mitre_raw else []
        
        mitre_tactics_raw = corr.get("mitre_tactics", "")
        if mitre_tactics_raw:
            mitre_tactics = [t.strip() for t in str(mitre_tactics_raw).split("|") if t.strip()]
        else:
            mitre_tactics = []

        # Check for Task 9 Attack Chain match
        chain_record = chain_map.get(corr_id)
        chain_stages = []

        if chain_record and chain_record.get("attack_stages"):
            raw_stages = str(chain_record["attack_stages"]).replace("→", "->").replace("\u2192", "->")
            stages_list = [s.strip() for s in raw_stages.split("->") if s.strip()]
            for idx, stage in enumerate(stages_list, start=1):
                tech = mitre_list[idx-1] if idx-1 < len(mitre_list) else (mitre_list[0] if mitre_list else None)
                chain_stages.append({
                    "stage_order": idx,
                    "tactic": stage,
                    "technique": tech,
                    "technique_name": stage,
                    "description": f"Stage {idx}: {stage} activity detected on {asset_id or 'target asset'}"
                })
            threat_type = f"Multi-Stage Attack Chain: {' -> '.join(stages_list)}"

        else:
            # For correlations without a Task 9 attack chain, do not manufacture fake sequential stages from mitre_techniques
            chain_stages = []
            threat_type = f"Correlated Activity: {', '.join(mitre_tactics)}" if mitre_tactics else "Correlated Threat Detection"

        risk_level, priority = classify_risk(risk_score)
        recommendations = get_recommendations_for_threat(threat_type, mitre_list)

        incident_id = f"INC-{inc_counter:03d}"
        inc_counter += 1

        incidents.append({
            "incident_id": incident_id,
            "event_ids": evt_ids,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "priority": priority,
            "asset_id": asset_id or "Unknown Asset",
            "affected_user": affected_user,
            "source_ip": source_ip,
            "mitre_techniques": mitre_list,
            "mitre_tactics": mitre_tactics,
            "status": "Open",
            "recommendations": recommendations,
            "attack_chain": chain_stages,
            "explainability": explainability,
            "event_count": len(evt_ids),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        })

    # 2. Process remaining un-correlated events into single incidents
    sorted_events = sorted(events_map.values(), key=lambda x: float(x.get("risk_score", 0)), reverse=True)
    for evt in sorted_events:
        eid = evt.get("event_id")
        if eid in seen_event_ids:
            continue

        risk_score = float(evt.get("risk_score", 0.0))
        if risk_score < 70.0 and len(incidents) >= 15:
            break

        seen_event_ids.add(eid)
        risk_level, priority = classify_risk(risk_score)
        threat_name = evt.get("ml_prediction") or evt.get("input_ml_prediction") or "Suspicious Event"
        asset_id = evt.get("asset_name") or evt.get("input_asset_name") or None
        
        user_val = evt.get("user_id") or evt.get("affected_user") or evt.get("input_user_id")
        affected_user = str(user_val).strip() if user_val and str(user_val).strip() and str(user_val).lower() != "nan" else None
        
        ip_val = evt.get("source_ip") or evt.get("input_source_ip")
        source_ip = str(ip_val).strip() if ip_val and str(ip_val).strip() and str(ip_val).lower() != "nan" else None

        recommendations = get_recommendations_for_threat(str(threat_name), [])
        explainability = get_event_explainability(evt)

        incident_id = f"INC-{inc_counter:03d}"
        inc_counter += 1

        incidents.append({
            "incident_id": incident_id,
            "event_ids": [eid],
            "threat_type": f"Security Event: {threat_name}",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "priority": priority,
            "asset_id": asset_id or "Unknown Asset",
            "affected_user": affected_user,
            "source_ip": source_ip,
            "mitre_techniques": [],
            "mitre_tactics": [],
            "status": "Open",
            "recommendations": recommendations,
            "attack_chain": [],
            "explainability": explainability,
            "event_count": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        })

    logger.info(f"Built {len(incidents)} SOC Incident objects.")
    return incidents


def run_import():
    if is_mongodb_available():
        db = get_database()
        db[settings.INCIDENTS_COLLECTION].delete_many({})
        logger.info(f"Cleared existing `{settings.INCIDENTS_COLLECTION}` collection for fresh seed.")

    incidents = build_incidents()
    logger.info(f"Persisting {len(incidents)} incidents to storage...")
    count = save_incidents_batch(incidents)
    logger.info(f"Successfully saved {count} incidents!")
    if is_mongodb_available():
        logger.info(f"MongoDB Collection `{settings.INCIDENTS_COLLECTION}` seeded successfully!")
    else:
        logger.info(f"Saved to local JSON store `{settings.INCIDENTS_JSON_PATH}`!")



if __name__ == "__main__":
    run_import()
