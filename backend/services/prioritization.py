"""
Milestone 3 - Task 7: Threat Prioritization
=============================================
Takes the output of Task 6 (calculate_risk / calculate_risk_batch) and
produces an ordered, analyst-ready incident list matching the team's
standard incident output contract.
"""

from risk_engine import calculate_risk_batch


VALID_STATUSES = {"Open", "Investigating", "Resolved", "False Positive"}


def prioritize_incidents(scored_events: list) -> list:
    """
    scored_events: list of dicts already produced by calculate_risk()
    (each must have `risk_score`, `risk_level`, `priority`, `reasons`).

    Sorts descending by risk_score. Ties broken by risk_level rank so
    "Critical" always sorts above "High" even at equal numeric scores
    (protects against floating point rounding edge cases).
    """
    level_rank = {"Critical": 5, "High": 4, "Moderate": 3, "Medium": 2, "Low": 1}

    def sort_key(evt):
        return (evt.get("risk_score", 0), level_rank.get(evt.get("risk_level"), 0))

    ordered = sorted(scored_events, key=sort_key, reverse=True)

    for evt in ordered:
        evt.setdefault("status", "Open")
        if evt["status"] not in VALID_STATUSES:
            evt["status"] = "Open"

    return ordered


def get_high_risk_events(scored_events: list, threshold: float = 61.0) -> list:
    """Returns events with risk_score >= threshold (default: High and above),
    already sorted by priority. threshold is on the 0-100 display scale."""
    filtered = [e for e in scored_events if e.get("risk_score", 0) >= threshold]
    return prioritize_incidents(filtered)


def score_and_prioritize(raw_events: list) -> list:
    """Convenience wrapper: Task 6 + Task 7 in one call."""
    scored = calculate_risk_batch(raw_events)
    return prioritize_incidents(scored)


def to_incident_summary(scored_event: dict, event_context: dict = None) -> dict:
    """
    Maps a Task 6 result into the fields Task 6/7 are responsible for within
    the team's shared incident JSON contract. Other fields (incident_id,
    affected_asset, related_events, mitre_techniques, recommendations) are
    filled in by Tasks 8-10 - this only returns the slice that's yours.
    """
    context = event_context or {}
    return {
        "event_id": scored_event["event_id"],
        "risk_score": scored_event["risk_score"],
        "risk_level": scored_event["risk_level"],
        "priority": scored_event["priority"],
        "reasons": scored_event["reasons"],
        "status": scored_event.get("status", "Open"),
        "ml_confidence": context.get("ml_confidence"),
        "ioc_status": context.get("ioc_status"),
    }
