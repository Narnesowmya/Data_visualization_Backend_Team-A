"""
Incident Repository for MongoDB collection `incidents` with local JSON backup fallback.
"""
import json
import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from config import settings
from database.m3_mongodb import get_database, is_mongodb_available

logger = logging.getLogger(__name__)

def _load_json_incidents() -> List[Dict[str, Any]]:
    if os.path.exists(settings.INCIDENTS_JSON_PATH):
        try:
            with open(settings.INCIDENTS_JSON_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading incidents.json: {e}")
    return []

def _save_json_incidents(incidents: List[Dict[str, Any]]) -> bool:
    try:
        os.makedirs(os.path.dirname(settings.INCIDENTS_JSON_PATH), exist_ok=True)
        with open(settings.INCIDENTS_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(incidents, f, indent=2, default=str)
        return True
    except Exception as e:
        logger.error(f"Error writing incidents.json: {e}")
        return False

def save_incident(incident_data: Dict[str, Any]) -> str:
    incident_id = incident_data.get("incident_id")
    if not incident_id:
        raise ValueError("incident_data must contain incident_id")

    incident_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    if "created_at" not in incident_data:
        incident_data["created_at"] = incident_data["updated_at"]

    if is_mongodb_available():
        db = get_database()
        collection = db[settings.INCIDENTS_COLLECTION]
        collection.update_one(
            {"incident_id": incident_id},
            {"$set": incident_data},
            upsert=True
        )

    # Always update local JSON as backup
    json_incidents = _load_json_incidents()
    existing_idx = next((i for i, item in enumerate(json_incidents) if item.get("incident_id") == incident_id), None)
    if existing_idx is not None:
        json_incidents[existing_idx] = incident_data
    else:
        json_incidents.append(incident_data)
    _save_json_incidents(json_incidents)

    return incident_id

def save_incidents_batch(incidents: List[Dict[str, Any]]) -> int:
    saved_count = 0
    if is_mongodb_available():
        db = get_database()
        collection = db[settings.INCIDENTS_COLLECTION]
        for inc in incidents:
            inc["updated_at"] = datetime.now(timezone.utc).isoformat()
            if "created_at" not in inc:
                inc["created_at"] = inc["updated_at"]
            collection.update_one(
                {"incident_id": inc["incident_id"]},
                {"$set": inc},
                upsert=True
            )
            saved_count += 1
    
    # Upsert batch into local JSON store
    json_incidents = _load_json_incidents()
    inc_map = {item["incident_id"]: idx for idx, item in enumerate(json_incidents) if isinstance(item, dict) and "incident_id" in item}
    for inc in incidents:
        iid = inc.get("incident_id")
        if iid in inc_map:
            json_incidents[inc_map[iid]] = inc
        else:
            json_incidents.append(inc)
            inc_map[iid] = len(json_incidents) - 1
    _save_json_incidents(json_incidents)

    if not is_mongodb_available():
        saved_count = len(incidents)

    return saved_count

def get_incidents(
    priority: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
    threat_type: Optional[str] = None,
    min_risk_score: Optional[float] = None,
    limit: int = 50,
    skip: int = 0
) -> List[Dict[str, Any]]:
    
    if is_mongodb_available():
        db = get_database()
        collection = db[settings.INCIDENTS_COLLECTION]
        query = {}
        if priority:
            query["priority"] = {"$regex": f"^{priority}$", "$options": "i"}
        if status:
            query["status"] = {"$regex": f"^{status}$", "$options": "i"}
        if asset_id:
            query["asset_id"] = {"$regex": asset_id, "$options": "i"}
        if threat_type:
            query["threat_type"] = {"$regex": threat_type, "$options": "i"}
        if min_risk_score is not None:
            query["risk_score"] = {"$gte": min_risk_score}

        cursor = collection.find(query, {"_id": 0}).sort("risk_score", -1).skip(skip).limit(limit)
        return list(cursor)

    # Fallback to local JSON store
    incidents = _load_json_incidents()
    filtered = []
    for inc in incidents:
        if priority and inc.get("priority", "").lower() != priority.lower():
            continue
        if status and inc.get("status", "").lower() != status.lower():
            continue
        if asset_id and asset_id.lower() not in inc.get("asset_id", "").lower():
            continue
        if threat_type and threat_type.lower() not in inc.get("threat_type", "").lower():
            continue
        if min_risk_score is not None and inc.get("risk_score", 0) < min_risk_score:
            continue
        filtered.append(inc)

    # Sort descending by risk_score
    filtered.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return filtered[skip : skip + limit]

def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    if is_mongodb_available():
        db = get_database()
        collection = db[settings.INCIDENTS_COLLECTION]
        return collection.find_one({"incident_id": incident_id}, {"_id": 0})

    incidents = _load_json_incidents()
    for inc in incidents:
        if inc.get("incident_id") == incident_id:
            return inc
    return None


def update_incident_status(incident_id: str, new_status: str) -> Optional[Dict[str, Any]]:
    updated_time = datetime.now(timezone.utc).isoformat()
    if is_mongodb_available():
        db = get_database()
        collection = db[settings.INCIDENTS_COLLECTION]
        res = collection.find_one_and_update(
            {"incident_id": incident_id},
            {"$set": {"status": new_status, "updated_at": updated_time}},
            projection={"_id": 0},
            return_document=True
        )
        if res:
            # Sync with local JSON
            json_incidents = _load_json_incidents()
            for idx, item in enumerate(json_incidents):
                if item.get("incident_id") == incident_id:
                    json_incidents[idx]["status"] = new_status
                    json_incidents[idx]["updated_at"] = updated_time
                    break
            _save_json_incidents(json_incidents)
            return res

    json_incidents = _load_json_incidents()
    for idx, item in enumerate(json_incidents):
        if item.get("incident_id") == incident_id:
            json_incidents[idx]["status"] = new_status
            json_incidents[idx]["updated_at"] = updated_time
            _save_json_incidents(json_incidents)
            return json_incidents[idx]
    return None

def delete_incident(incident_id: str) -> bool:
    if is_mongodb_available():
        db = get_database()
        collection = db[settings.INCIDENTS_COLLECTION]
        collection.delete_one({"incident_id": incident_id})

    json_incidents = _load_json_incidents()
    filtered = [inc for inc in json_incidents if inc.get("incident_id") != incident_id]
    if len(filtered) != len(json_incidents):
        _save_json_incidents(filtered)
        return True
    return False

def get_risk_summary() -> Dict[str, Any]:

    all_incidents = get_incidents(limit=10000)
    total = len(all_incidents)

    priority_counts = {
        "Immediate Investigation": 0,
        "Investigate Soon": 0,
        "Review When Possible": 0,
        "Monitor": 0,
        "No Action Needed": 0,
    }
    status_counts = {"Open": 0, "Investigating": 0, "Resolved": 0, "False Positive": 0}
    asset_scores: Dict[str, Dict[str, Any]] = {}
    total_score = 0.0

    for inc in all_incidents:
        p = inc.get("priority", "Low")
        priority_counts[p] = priority_counts.get(p, 0) + 1
        
        s = inc.get("status", "Open")
        status_counts[s] = status_counts.get(s, 0) + 1
        
        score = inc.get("risk_score", 0.0)
        total_score += score

        asset = inc.get("asset_id", "Unknown")
        if asset not in asset_scores:
            asset_scores[asset] = {"asset_id": asset, "count": 0, "max_risk": 0.0}
        asset_scores[asset]["count"] += 1
        if score > asset_scores[asset]["max_risk"]:
            asset_scores[asset]["max_risk"] = score

    top_assets = sorted(list(asset_scores.values()), key=lambda x: (x["max_risk"], x["count"]), reverse=True)[:5]
    avg_score = round(total_score / total, 1) if total > 0 else 0.0

    return {
        "total_incidents": total,
        "open_incidents": status_counts.get("Open", 0),
        "investigating_incidents": status_counts.get("Investigating", 0),
        "resolved_incidents": status_counts.get("Resolved", 0),
        "false_positive_incidents": status_counts.get("False Positive", 0),
        "priority_counts": priority_counts,
        "status_counts": status_counts,
        "average_risk_score": avg_score,
        "top_assets": top_assets
    }

def get_attack_chains() -> List[Dict[str, Any]]:
    """Return the approved Task 8/9 TIMEWINDOW attack-chain output directly."""
    path = settings.ATTACK_CHAINS_JSON
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.error(f"Error reading attack_chains.json: {e}")
        return []
