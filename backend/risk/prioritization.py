"""
Milestone 3 - Task 7: Threat Prioritization Engine
==================================================
Sorts security incidents descending by risk score, breaking ties using risk level rank.
"""

LEVEL_RANK = {
    "Critical": 5,
    "High": 4,
    "Moderate": 3,
    "Medium": 2,
    "Low": 1
}

def prioritize_incidents(incidents: list) -> list:
    """
    Sorts a list of incidents/events by risk_score descending.
    """
    def sort_key(item):
        score = item.get("risk_score", 0.0)
        level = item.get("risk_level", item.get("priority", "Low"))
        rank = LEVEL_RANK.get(level, 1)
        return (score, rank)

    sorted_incidents = sorted(incidents, key=sort_key, reverse=True)
    
    # Assign ranks
    for idx, inc in enumerate(sorted_incidents, start=1):
        inc["rank"] = idx

    return sorted_incidents
