"""
Milestone 3 - Task 6: Risk Score Engine
=========================================

Scale convention (per team agreement, confirmed by mentor):
    ALL internal risk factors are normalized to 0-1 before being combined.
    The final `risk_score` field returned to the API / frontend is displayed
    on a 0-100 scale for readability, but every internal calculation uses 0-1.

Weights (locked, from Milestone_3_Design.md):
    Threat Severity      -> 0.25
    ML Confidence         -> 0.25
    Asset Criticality     -> 0.20
    Vulnerability Risk    -> 0.20
    Threat Intelligence   -> 0.10

Risk Categories (0-1 internal scale):
    0.00 - 0.20   -> Low
    0.21 - 0.40   -> Medium
    0.41 - 0.60   -> Moderate
    0.61 - 0.80   -> High
    0.81 - 1.00   -> Critical
"""

from datetime import datetime, timezone
import math


# ---------------------------------------------------------------------------
# 1. Weights
# ---------------------------------------------------------------------------

WEIGHTS = {
    "threat_severity": 0.25,
    "ml_confidence": 0.25,
    "asset_criticality": 0.20,
    "vulnerability_exposure": 0.20,
    "threat_intelligence": 0.10,
}

assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "Weights must sum to 1.0"


# ---------------------------------------------------------------------------
# 2. Normalization helpers -> all return values on a 0-1 scale
# ---------------------------------------------------------------------------

def normalize_confidence(confidence_score: float) -> float:
    """M2 ml_confidence arrives as 0-100 (e.g. 92). Convert to 0-1."""
    if confidence_score is None:
        return 0.0
    value = confidence_score / 100 if confidence_score > 1 else confidence_score
    return _clamp01(value)


def normalize_cvss(cvss_score: float) -> float:
    """CVSS is 0-10. Convert to 0-1."""
    if cvss_score is None:
        return 0.0
    return _clamp01(cvss_score / 10)


def severity_to_score(severity: str) -> float:
    mapping = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
    return mapping.get(severity, 0.5)


def criticality_to_score(criticality: str):
    """Convert a verified criticality label to 0-1.

    Unknown, missing, or unrecognized criticality is returned as None. It must
    never be silently converted to Medium (0.5), because that would fabricate
    an asset property that is not present in the asset master.
    """
    mapping = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
    return mapping.get(criticality)


def ioc_to_score(ioc_status: str, ioc_confidence: str = None) -> float:
    """Task 5 output. Expects ioc_status in {"Malicious", "Suspicious", "Clean"}.
    Unrecognized / "No Match" / None values default to 0.0 (treated as Clean)."""
    if ioc_status == "Malicious":
        return 1.0 if ioc_confidence == "High" else 0.75
    elif ioc_status == "Suspicious":
        return 0.5
    return 0.0


def _is_missing(value) -> bool:
    """True for None/NaN values received directly or through pandas."""
    return value is None or (isinstance(value, float) and math.isnan(value))


def _clamp01(value: float) -> float:
    return min(max(value, 0.0), 1.0)


# ---------------------------------------------------------------------------
# 3. Weighted formula
# ---------------------------------------------------------------------------

def calculate_risk_score(threat_severity: float, ml_confidence: float,
                          asset_criticality, vulnerability_exposure: float,
                          threat_intelligence: float) -> float:
    """Return a 0-1 weighted risk score.

    The locked factor weights are unchanged. If a component is genuinely
    unknown (currently asset criticality), that component is omitted rather
    than assigned a fabricated value. The weighted sum is divided by the
    weight of the available components, preserving the original relative
    weights among known evidence.

    Example: unknown asset criticality leaves 0.80 of the configured weight
    available, so score = known_weighted_sum / 0.80.
    """
    values = {
        "threat_severity": threat_severity,
        "ml_confidence": ml_confidence,
        "asset_criticality": asset_criticality,
        "vulnerability_exposure": vulnerability_exposure,
        "threat_intelligence": threat_intelligence,
    }
    available = {k: v for k, v in values.items() if not _is_missing(v)}
    available_weight = sum(WEIGHTS[k] for k in available)
    if available_weight <= 0:
        return 0.0
    weighted_sum = sum(_clamp01(v) * WEIGHTS[k] for k, v in available.items())
    return round(_clamp01(weighted_sum / available_weight), 4)


# ---------------------------------------------------------------------------
# 4. Risk level classification (0-1 scale)
# ---------------------------------------------------------------------------

def classify_risk(score: float) -> str:
    if score >= 0.81:
        return "Critical"
    elif score >= 0.61:
        return "High"
    elif score >= 0.41:
        return "Moderate"
    elif score >= 0.21:
        return "Medium"
    else:
        return "Low"


# ---------------------------------------------------------------------------
# 5. Risk level -> priority action label
# ---------------------------------------------------------------------------

def risk_level_to_priority(risk_level: str) -> str:
    mapping = {
        "Critical": "Immediate Investigation",
        "High": "Investigate Soon",
        "Moderate": "Review When Possible",
        "Medium": "Monitor",
        "Low": "No Action Needed",
    }
    return mapping.get(risk_level, "Monitor")


# ---------------------------------------------------------------------------
# 6. Reasons generator (explains WHY a score came out the way it did)
# ---------------------------------------------------------------------------

def generate_reasons(threat_severity: float, ml_confidence: float,
                      asset_criticality: float, vulnerability_exposure: float,
                      threat_intelligence: float, failed_login_attempts: int = 0,
                      after_hours: bool = False) -> list:
    reasons = []
    if asset_criticality is not None and asset_criticality >= 0.90:
        reasons.append("Critical asset")
    if ml_confidence >= 0.85:
        reasons.append("High ML confidence")
    if vulnerability_exposure >= 0.80:
        reasons.append("High CVSS vulnerability")
    if threat_intelligence >= 0.90:
        reasons.append("Malicious IOC")
    if failed_login_attempts >= 5:
        reasons.append("Multiple failed login attempts")
    if after_hours:
        reasons.append("After-hours activity")
    return reasons


# ---------------------------------------------------------------------------
# 7. Main entry point - takes one raw event dict, returns the full risk result
# ---------------------------------------------------------------------------

def calculate_risk(event: dict) -> dict:
    """
    Expected keys on `event` (raw, from the shared risk_factors contract):
        event_id, severity, ml_confidence, asset_criticality (label,
        e.g. "Critical") OR asset_criticality_score (0-1, preferred if present),
        cvss_score, ioc_status, ioc_confidence,
        failed_login_attempts (optional), after_hours (optional)
    """
    severity_score = severity_to_score(event.get("severity"))
    confidence_score = normalize_confidence(event.get("ml_confidence"))

    # prefer a pre-normalized 0-1 criticality score if the caller already has one
    # (e.g. straight from Task 2's asset_criticality.csv), else derive from label
    raw_criticality_score = event.get("asset_criticality_score")
    if not _is_missing(raw_criticality_score):
        criticality_score = _clamp01(raw_criticality_score)
    else:
        criticality_score = criticality_to_score(event.get("asset_criticality"))

    vuln_score = normalize_cvss(event.get("cvss_score"))
    intel_score = ioc_to_score(event.get("ioc_status"), event.get("ioc_confidence"))

    risk_score_raw = calculate_risk_score(
        severity_score, confidence_score, criticality_score, vuln_score, intel_score
    )
    missing_components = []
    if criticality_score is None:
        missing_components.append("asset_criticality")
    available_weight = round(1.0 - sum(WEIGHTS[c] for c in missing_components), 4)

    risk_level = classify_risk(risk_score_raw)
    priority = risk_level_to_priority(risk_level)
    reasons = generate_reasons(
        severity_score, confidence_score, criticality_score, vuln_score, intel_score,
        failed_login_attempts=event.get("failed_login_attempts", 0) or 0,
        after_hours=event.get("after_hours", False) or False,
    )

    return {
        "event_id": event.get("event_id"),
        "risk_score_internal": risk_score_raw,             # 0-1, internal use
        "risk_score": round(risk_score_raw * 100, 2),       # 0-100, for API/frontend
        "risk_level": risk_level,
        "priority": priority,
        "risk_score_complete": len(missing_components) == 0,
        "missing_components": missing_components,
        "component_weight_coverage": available_weight,
        "asset_criticality_score": criticality_score,
        "reasons": reasons,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }


def calculate_risk_batch(events: list) -> list:
    """Run calculate_risk() over a list of raw event dicts."""
    return [calculate_risk(e) for e in events]
