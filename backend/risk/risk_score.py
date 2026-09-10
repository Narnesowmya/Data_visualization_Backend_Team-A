"""
Milestone 3 - Task 6: Risk Assessment Engine (Approved Task 6/7 Logic)
=======================================================================
Calculates risk scores (0-100 scale) based on 5 weighted factors:
1. Threat Severity (25%)
2. ML Confidence (25%)
3. Asset Criticality (20%) - Left NULL if missing/Unknown, available weights re-normalized
4. Vulnerability Exposure / CVSS (20%)
5. Threat Intelligence / IOC (10%)
"""
import math
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

WEIGHTS = {
    "threat_severity": 0.25,
    "ml_confidence": 0.25,
    "asset_criticality": 0.20,
    "vulnerability_exposure": 0.20,
    "threat_intelligence": 0.10
}

def _clamp01(val: float) -> float:
    return min(max(val, 0.0), 1.0)

def _is_missing(val: Any) -> bool:
    if val is None:
        return True
    if isinstance(val, float) and math.isnan(val):
        return True
    if isinstance(val, str) and val.strip().lower() in ["unknown", "none", "", "null"]:
        return True
    return False

def severity_to_score(severity: Any) -> float:
    if _is_missing(severity):
        return 0.5
    s = str(severity).strip().lower()
    if "crit" in s: return 1.0
    if "high" in s: return 0.75
    if "med" in s or "mod" in s: return 0.50
    if "low" in s: return 0.25
    return 0.50

def normalize_confidence(ml_confidence: Any) -> float:
    if _is_missing(ml_confidence):
        return 0.0
    try:
        val = float(ml_confidence)
        if val > 1.0:
            val = val / 100.0
        return _clamp01(val)
    except (ValueError, TypeError):
        return 0.0

def criticality_to_score(criticality: Any) -> Optional[float]:
    """
    Approved Task 6/7 Logic:
    Unknown/missing criticality returns None. Never fabricate 0.5 (Medium).
    """
    if _is_missing(criticality):
        return None
    s = str(criticality).strip().lower()
    if "crit" in s: return 1.0
    if "high" in s: return 0.75
    if "med" in s or "mod" in s: return 0.50
    if "low" in s: return 0.25
    return None

def normalize_cvss(cvss_score: Any) -> float:
    if _is_missing(cvss_score):
        return 0.0
    try:
        val = float(cvss_score)
        if val > 10.0:
            val = val / 10.0
        elif val > 1.0:
            val = val / 10.0
        return _clamp01(val)
    except (ValueError, TypeError):
        return 0.0

def ioc_to_score(ioc_status: Any, ioc_confidence: Any = None) -> float:
    if _is_missing(ioc_status):
        return 0.0
    s = str(ioc_status).strip().lower()
    conf = str(ioc_confidence).strip().lower() if ioc_confidence else ""
    if "malic" in s:
        return 1.0 if conf == "high" else 0.75
    if "susp" in s:
        return 0.50
    return 0.0

def calculate_risk_score(
    threat_severity: float,
    ml_confidence: float,
    asset_criticality: Optional[float],
    vulnerability_exposure: float,
    threat_intelligence: float
) -> float:
    """
    Calculates 0-1 normalized risk score using available weights.
    If asset_criticality is None, available_weight is 0.80, preserving original factor balance.
    """
    values = {
        "threat_severity": threat_severity,
        "ml_confidence": ml_confidence,
        "asset_criticality": asset_criticality,
        "vulnerability_exposure": vulnerability_exposure,
        "threat_intelligence": threat_intelligence,
    }
    available = {k: v for k, v in values.items() if v is not None}
    available_weight = sum(WEIGHTS[k] for k in available)
    if available_weight <= 0:
        return 0.0
    weighted_sum = sum(_clamp01(v) * WEIGHTS[k] for k, v in available.items())
    return round(_clamp01(weighted_sum / available_weight), 4)

def classify_risk(risk_score_100: float) -> tuple:
    """
    Maps 0-100 score to (risk_level, priority_action).
    Consistent with Task 7 priority vocabulary.
    """
    score_0to1 = risk_score_100 / 100.0 if risk_score_100 > 1.0 else risk_score_100
    if score_0to1 >= 0.81:
        return ("Critical", "Immediate Investigation")
    elif score_0to1 >= 0.61:
        return ("High", "Investigate Soon")
    elif score_0to1 >= 0.41:
        return ("Moderate", "Review When Possible")
    elif score_0to1 >= 0.21:
        return ("Medium", "Monitor")
    else:
        return ("Low", "No Action Needed")

def generate_reasons(
    severity_score: float,
    confidence_score: float,
    criticality_score: Optional[float],
    vuln_score: float,
    intel_score: float,
    failed_logins: int = 0
) -> List[str]:
    reasons = []
    if criticality_score is not None and criticality_score >= 0.75:
        reasons.append("Critical or High Criticality Asset Targeted")
    if confidence_score >= 0.85:
        reasons.append("High ML Threat Confidence")
    if vuln_score >= 0.80:
        reasons.append("High CVSS Vulnerability Exposure")
    if intel_score >= 0.75:
        reasons.append("Malicious Threat Intelligence IOC Match")
    if failed_logins >= 5:
        reasons.append("Multiple Failed Login Attempts Detected")
    if severity_score >= 0.75:
        reasons.append("High Security Severity Level")

    if not reasons:
        reasons.append("Routine Monitoring Flag")
    return reasons

def calculate_risk(event: Dict[str, Any]) -> Dict[str, Any]:
    event_id = event.get("event_id", "EVT-UNKNOWN")
    
    sev_score = severity_to_score(event.get("severity"))
    conf_score = normalize_confidence(event.get("ml_confidence", event.get("confidence_score")))
    
    raw_crit = event.get("asset_criticality_score", event.get("asset_criticality_score_0to1"))
    if not _is_missing(raw_crit):
        try:
            crit_score = _clamp01(float(raw_crit))
        except (ValueError, TypeError):
            crit_score = criticality_to_score(event.get("asset_criticality"))
    else:
        crit_score = criticality_to_score(event.get("asset_criticality"))

    vuln_score = normalize_cvss(event.get("cvss_score"))
    intel_score = ioc_to_score(event.get("ioc_status"), event.get("ioc_confidence"))

    risk_score_raw = calculate_risk_score(sev_score, conf_score, crit_score, vuln_score, intel_score)
    final_score_100 = round(risk_score_raw * 100.0, 2)
    
    risk_level, priority = classify_risk(final_score_100)
    reasons = generate_reasons(sev_score, conf_score, crit_score, vuln_score, intel_score, event.get("failed_login_attempts", 0) or 0)

    missing_components = []
    if crit_score is None:
        missing_components.append("asset_criticality")
    
    available_weight = round(1.0 - sum(WEIGHTS[c] for c in missing_components), 4)

    return {
        "event_id": event_id,
        "risk_score_internal": risk_score_raw,
        "risk_score": final_score_100,
        "risk_level": risk_level,
        "priority": priority,
        "reasons": reasons,
        "missing_components": missing_components,
        "component_weight_coverage": available_weight,
        "explainability": {
            "severity_weight_pct": 25.0,
            "severity_score": round(sev_score * 100.0, 2),
            "ml_confidence_weight_pct": 25.0,
            "ml_confidence_score": round(conf_score * 100.0, 2),
            "asset_criticality_weight_pct": 20.0,
            "asset_criticality_score": round(crit_score * 100.0, 2) if crit_score is not None else None,
            "vulnerability_weight_pct": 20.0,
            "vulnerability_score": round(vuln_score * 100.0, 2),
            "threat_intel_weight_pct": 10.0,
            "threat_intel_score": round(intel_score * 100.0, 2),
            "reasons": reasons
        },
        "calculated_at": datetime.now(timezone.utc).isoformat()
    }

def calculate_risk_batch(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [calculate_risk(e) for e in events]
