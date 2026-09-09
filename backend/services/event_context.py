"""Event context enrichment for Task 10/11 incident responses."""
from functools import lru_cache
from typing import Any, Dict, List
import csv
from config import settings

@lru_cache(maxsize=1)
def _load_event_context() -> Dict[str, Dict[str, Any]]:
    path = settings.DATA_DIR / "m3_task1_inputs.csv"
    if not path.exists():
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            result[row.get("event_id", "")] = row
    return result

def enrich_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Add non-breaking related_events details from the existing M3 event dataset."""
    enriched = dict(incident)
    if enriched.get("related_events"):
        return enriched
    context = _load_event_context()
    related: List[Dict[str, Any]] = []
    for event_id in enriched.get("event_ids", []) or []:
        row = context.get(str(event_id))
        if not row:
            continue
        event_type = (row.get("event_type") or "Security event").strip()
        severity = (row.get("severity") or "").strip()
        description = f"{event_type} detected"
        if severity:
            description += f" (Severity: {severity})"
        related.append({
            "event_id": str(event_id),
            "timestamp": row.get("timestamp") or "",
            "source_ip": row.get("source_ip") or None,
            "description": description,
        })
    enriched["related_events"] = related
    return enriched

def enrich_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_incident(item) for item in incidents]
