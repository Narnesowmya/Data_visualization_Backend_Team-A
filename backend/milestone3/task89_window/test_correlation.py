import pandas as pd
from event_correlation import correlate_events
from attack_chain import build_attack_chains


def _context_df():
    return pd.DataFrame([
        {"event_type":"Brute Force","mitre_id":"T1110","technique_name":"Brute Force","tactic":"Credential Access"},
        {"event_type":"Privilege Escalation","mitre_id":"T1068","technique_name":"Exploitation for Privilege Escalation","tactic":"Privilege Escalation"},
    ])


def _enrich(df):
    ctx = _context_df()
    tm = ctx.groupby("event_type")["mitre_id"].apply(lambda s: "|".join(sorted(set(s)))).to_dict()
    am = ctx.groupby("event_type")["tactic"].apply(lambda s: "|".join(sorted(set(s)))).to_dict()
    df = df.copy()
    df["mitre_techniques"] = df.event_type.map(tm).fillna("")
    df["mitre_tactics"] = df.event_type.map(am).fillna("")
    df["timestamp"] = pd.to_datetime(df.timestamp)
    return df


def test_same_asset_within_window_correlates():
    df = _enrich(pd.DataFrame([
        {"event_id":"E1","event_type":"Brute Force","asset_name":"A","source_ip":"1.1.1.1","timestamp":"2026-01-01 10:00:00"},
        {"event_id":"E2","event_type":"Privilege Escalation","asset_name":"A","source_ip":"2.2.2.2","timestamp":"2026-01-01 10:10:00"},
    ]))
    out = correlate_events(df)
    assert len(out) == 1
    assert out.iloc[0]["event_count"] == 2
    assert out.iloc[0]["window_minutes"] == 10


def test_same_asset_outside_window_does_not_correlate():
    df = _enrich(pd.DataFrame([
        {"event_id":"E1","event_type":"Brute Force","asset_name":"A","source_ip":"1.1.1.1","timestamp":"2026-01-01 10:00:00"},
        {"event_id":"E2","event_type":"Privilege Escalation","asset_name":"A","source_ip":"2.2.2.2","timestamp":"2026-01-01 10:31:00"},
    ]))
    out = correlate_events(df)
    assert len(out) == 0


def test_multistage_attack_chain_inherits_task7_risk():
    corr = pd.DataFrame([{
        "correlation_id":"C1","event_ids":"E1|E2","event_count":2,
        "rule":"asset_time_window","mitre_techniques":"T1110|T1068",
        "mitre_tactics":"Credential Access|Privilege Escalation",
        "start_time":"2026-01-01 10:00:00","end_time":"2026-01-01 10:10:00",
        "window_minutes":10,"asset_name":"A","source_ip":"1.1.1.1|2.2.2.2"
    }])
    pri = pd.DataFrame([
        {"event_id":"E1","risk_score":80,"risk_level":"High"},
        {"event_id":"E2","risk_score":60,"risk_level":"Moderate"},
    ])
    out = build_attack_chains(corr, pri)
    assert len(out) == 1
    assert out.iloc[0]["risk_score"] == 80
    assert out.iloc[0]["risk_level"] == "High"
    assert "Credential Access" in out.iloc[0]["attack_stages"]
    assert "Privilege Escalation" in out.iloc[0]["attack_stages"]


if __name__ == "__main__":
    test_same_asset_within_window_correlates()
    test_same_asset_outside_window_does_not_correlate()
    test_multistage_attack_chain_inherits_task7_risk()
    print("3/3 tests passed")
