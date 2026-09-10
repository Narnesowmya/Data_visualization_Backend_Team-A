"""
Test suite for Task 6 / Task 7.
Run with: python3 test_risk_engine.py
"""

from risk_engine import calculate_risk, classify_risk, calculate_risk_score
from prioritization import prioritize_incidents, get_high_risk_events


def test_mentor_worked_example():
    """EVT-1001 from the mentor's practical implementation doc:
    Brute Force, ML Confidence 92%, Asset=Production DB (Critical),
    CVSS 9.2, IOC=Malicious, 25 failed logins, after-hours.
    Expected: Risk Score ~95, Risk Level Critical, Priority Immediate Investigation."""
    event = {
        "event_id": "EVT-1001",
        "severity": "High",              # brute force -> treated as High severity input
        "ml_confidence": 92,
        "asset_criticality": "Critical",
        "cvss_score": 9.2,
        "ioc_status": "Malicious",
        "ioc_confidence": "High",
        "failed_login_attempts": 25,
        "after_hours": True,
    }
    result = calculate_risk(event)
    print(f"EVT-1001 -> risk_score={result['risk_score']}, "
          f"risk_level={result['risk_level']}, priority={result['priority']}")
    print(f"  reasons={result['reasons']}")

    assert result["risk_level"] == "Critical", "Expected Critical risk level"
    assert result["priority"] == "Immediate Investigation"
    assert result["risk_score"] >= 81, "Expected risk_score in the Critical band (>=81)"
    assert "Critical asset" in result["reasons"]
    assert "Malicious IOC" in result["reasons"]
    assert "Multiple failed login attempts" in result["reasons"]
    assert "After-hours activity" in result["reasons"]
    print("  PASSED\n")


def test_mocked_malicious_ioc_increases_risk():
    """Doc requirement (Task 5, Section 9): 'If an event is associated with a
    known malicious IOC, its risk should increase.' Task 5's real matching is
    not yet producing verified matches, so this proves Task 6's logic honors
    that rule using a manually mocked malicious case."""
    base_event = {
        "event_id": "EVT-CLEAN",
        "severity": "Medium",
        "ml_confidence": 60,
        "asset_criticality": "Medium",
        "cvss_score": 5.0,
        "ioc_status": "Clean",
    }
    malicious_event = dict(base_event, event_id="EVT-MALICIOUS", ioc_status="Malicious",
                            ioc_confidence="High")

    clean_result = calculate_risk(base_event)
    malicious_result = calculate_risk(malicious_event)

    print(f"Clean IOC     -> risk_score={clean_result['risk_score']}")
    print(f"Malicious IOC -> risk_score={malicious_result['risk_score']}")

    assert malicious_result["risk_score"] > clean_result["risk_score"], \
        "Malicious IOC must increase the risk score vs an otherwise identical Clean event"
    print("  PASSED\n")


def test_low_criticality_low_cvss_scores_low():
    """Case A from mentor doc: Brute Force, ML Confidence 90%, Employee Laptop,
    CVSS 2.0 -> expected Medium/High, NOT Critical."""
    event = {
        "event_id": "EVT-LAPTOP",
        "severity": "Medium",
        "ml_confidence": 90,
        "asset_criticality": "Medium",   # Employee Laptop
        "cvss_score": 2.0,
        "ioc_status": "Clean",
    }
    result = calculate_risk(event)
    print(f"EVT-LAPTOP -> risk_score={result['risk_score']}, risk_level={result['risk_level']}")
    assert result["risk_level"] in ("Medium", "Moderate", "High"), \
        "Low-criticality low-CVSS event should not be Critical"
    assert result["risk_level"] != "Critical"
    print("  PASSED\n")


def test_cvss_does_not_equal_risk_score():
    """Doc explicitly warns: CVSS 9.8 does NOT mean Risk Score 98.
    Confirms vulnerability is only 20% of the formula, not the whole score."""
    event = {
        "event_id": "EVT-HIGHCVSS-ONLY",
        "severity": "Low",
        "ml_confidence": 20,
        "asset_criticality": "Low",
        "cvss_score": 9.8,
        "ioc_status": "Clean",
    }
    result = calculate_risk(event)
    print(f"High CVSS alone -> risk_score={result['risk_score']} (should be far below 98)")
    assert result["risk_score"] < 60, "A single high-CVSS factor should not dominate the score"
    print("  PASSED\n")


def test_weights_sum_to_one():
    from risk_engine import WEIGHTS
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9
    print("Weights sum check -> PASSED\n")


def test_prioritization_sorts_descending():
    events = [
        calculate_risk({"event_id": "A", "severity": "Low", "ml_confidence": 20,
                         "asset_criticality": "Low", "cvss_score": 1.0, "ioc_status": "Clean"}),
        calculate_risk({"event_id": "B", "severity": "Critical", "ml_confidence": 95,
                         "asset_criticality": "Critical", "cvss_score": 9.5,
                         "ioc_status": "Malicious", "ioc_confidence": "High"}),
        calculate_risk({"event_id": "C", "severity": "Medium", "ml_confidence": 55,
                         "asset_criticality": "Medium", "cvss_score": 5.0, "ioc_status": "Clean"}),
    ]
    ordered = prioritize_incidents(events)
    ids_in_order = [e["event_id"] for e in ordered]
    print(f"Priority order -> {ids_in_order}")

    assert ids_in_order[0] == "B", "Highest risk event must come first"
    assert ids_in_order[-1] == "A", "Lowest risk event must come last"
    for e in ordered:
        assert e["status"] == "Open", "Default status must be Open"
    print("  PASSED\n")


def test_get_high_risk_events_filters_correctly():
    events = [
        calculate_risk({"event_id": "LOW1", "severity": "Low", "ml_confidence": 10,
                         "asset_criticality": "Low", "cvss_score": 1.0, "ioc_status": "Clean"}),
        calculate_risk({"event_id": "CRIT1", "severity": "Critical", "ml_confidence": 95,
                         "asset_criticality": "Critical", "cvss_score": 9.5,
                         "ioc_status": "Malicious", "ioc_confidence": "High"}),
    ]
    high_risk = get_high_risk_events(events, threshold=61.0)
    ids = [e["event_id"] for e in high_risk]
    print(f"High risk filter -> {ids}")
    assert "CRIT1" in ids
    assert "LOW1" not in ids
    print("  PASSED\n")


if __name__ == "__main__":
    test_mentor_worked_example()
    test_mocked_malicious_ioc_increases_risk()
    test_low_criticality_low_cvss_scores_low()
    test_cvss_does_not_equal_risk_score()
    test_weights_sum_to_one()
    test_prioritization_sorts_descending()
    test_get_high_risk_events_filters_correctly()
    print("=" * 50)
    print("ALL TASK 6 / TASK 7 TESTS PASSED")
    print("=" * 50)

# Missing asset criticality regression tests (added after gap review)
def test_unknown_asset_criticality_is_null_not_medium():
    event = {
        "event_id": "EVT-UNKNOWN-ASSET",
        "severity": "High",
        "ml_confidence": 80,
        "asset_criticality": "Unknown",
        "asset_criticality_score": None,
        "cvss_score": 8.0,
        "ioc_status": "Clean",
    }
    result = calculate_risk(event)
    assert result["asset_criticality_score"] is None
    assert result["risk_score_complete"] is False
    assert result["missing_components"] == ["asset_criticality"]
    assert result["component_weight_coverage"] == 0.8


def test_unknown_asset_does_not_assume_medium():
    common = {
        "severity": "High", "ml_confidence": 80, "cvss_score": 8.0,
        "ioc_status": "Clean"
    }
    unknown = calculate_risk(dict(common, event_id="UNKNOWN", asset_criticality="Unknown"))
    medium = calculate_risk(dict(common, event_id="MEDIUM", asset_criticality="Medium"))
    # Missing-component normalization is intentionally different from inserting 0.5.
    assert unknown["asset_criticality_score"] is None
    assert unknown["risk_score"] != medium["risk_score"]
