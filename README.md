🛡️ Vigilion Backend

Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics

Group 2

Backend services for the Vigilion Security Operations Dashboard, providing risk calculation, threat enrichment, vulnerability exposure, event correlation, attack-chain context, incident management, and analyst recommendations.

📌 Overview

The Vigilion Backend provides the security intelligence and risk-processing layer behind the Vigilion SOC dashboard.

It takes security-event and threat-context data and transforms it into:

Risk scores

Risk levels

Investigation priorities

Threat intelligence context

Vulnerability exposure

Event correlations

Attack-chain context

Incidents

Risk explanations

Response recommendations

The frontend consumes these backend results through REST APIs and focuses on presenting the information to SOC analysts.

🎯 Backend Objective

The backend is designed around the SOC question:

How dangerous is this event, and should the security analyst investigate it first?

The processing flow is:

Security Event
      │
      ▼
Threat Enrichment
      │
      ├── IOC Context
      ├── MITRE ATT&CK Context
      ├── Vulnerability Context
      └── Asset Criticality
      │
      ▼
Risk Calculation
      │
      ▼
Event Correlation
      │
      ▼
Incident Creation
      │
      ▼
Priority & Recommendations

✨ Key Capabilities

Capability

Purpose

🚨 Risk Calculation

Calculate normalized event risk and display a 0–100 risk score

🧠 ML Context

Use prediction, confidence, and anomaly information as risk inputs

🛡️ Asset Criticality

Account for the importance of the affected asset

🔐 Vulnerability Exposure

Incorporate CVSS and vulnerability exposure into risk

🔎 IOC Enrichment

Identify malicious or suspicious IOC context

🧩 MITRE ATT&CK Context

Map event types to ATT&CK techniques and tactics

🔗 Event Correlation

Connect related security events within defined time windows

⛓️ Attack Chains

Preserve authentic correlated attack-stage sequences

🚨 Incident Management

Create, retrieve, and update security incidents

🧠 Explainability

Provide reasons supporting the calculated risk

📋 Recommendations

Generate investigation-oriented response guidance

🧪 Validation & Testing

Validate backend behavior through automated tests

🧮 Risk Scoring

The backend uses the approved Milestone 3 risk model:

Risk Score =
    Threat Severity       × 0.25
  + ML Confidence         × 0.25
  + Asset Criticality     × 0.20
  + Vulnerability Risk    × 0.20
  + Threat Intelligence   × 0.10

The components are normalized internally to a 0–1 scale and the final displayed score is converted to 0–100.

Risk Categories

Score

Risk Level

0–20

Low

21–40

Medium

41–60

Moderate

61–80

High

81–100

Critical

Priority Mapping

Risk Level

Investigation Priority

Critical

Immediate Investigation

High

Investigate Soon

Moderate

Review When Possible

Medium

Monitor

Low

No Action Needed

🛡️ Asset Criticality

Asset criticality is represented separately from vulnerability exposure.

Asset Criticality

Score

Critical

1.00

High

0.75

Medium

0.50

Low

0.25

When asset criticality is unavailable, the backend does not invent a replacement value. The available risk components are renormalized over their available weight.

🔐 Vulnerability Exposure

Vulnerability exposure is calculated using CVSS and vulnerability status.

Vulnerability Exposure Score =
    (CVSS Score / 10) × Status Multiplier

Status multipliers:

Vulnerability Status

Multiplier

Open

1.00

In Progress

1.00

Won't Fix

1.00

Patched

0.25

Closed

0.10

For an event-level risk calculation, the highest applicable vulnerability exposure for the affected asset is used as the vulnerability-risk component.

🔎 IOC Enrichment

The backend enriches security events using threat-intelligence indicators.

The IOC workflow is:

Security Event
      │
      ▼
Genuine Source/Destination IOC Matching
      │
      ├── Match → IOC enrichment
      │
      └── No Match
             │
             ▼
       Approved synthetic
       demonstration mapping
             │
             ▼
       Enriched event result

IOC results distinguish between:

Malicious

Suspicious

No IOC Match

Unmatched IOC fields remain null rather than being populated with fabricated values.

🧩 MITRE ATT&CK Context

MITRE ATT&CK information is maintained as reusable context mapped from security event types.

The mapping provides:

MITRE technique IDs

Technique names

Tactics

Event-type context

MITRE techniques and tactics are supporting investigation context.

They are not automatically treated as chronological attack stages.

Authentic attack stages are consumed from the event-correlation / attack-chain output when a valid attack chain exists.

🔗 Event Correlation

Related security events can be grouped using correlation rules based on:

Same asset

Same source IP

Same user

Multiple suspicious events

Short time windows

Related security activity

Correlation output contains information such as:

correlation_id
rule
event_ids
asset_name
source_ip
event_types
mitre_techniques
mitre_tactics
start_time
end_time
window_minutes
event_count

⛓️ Attack Chain Context

When a valid correlated attack chain exists, the backend preserves the authentic attack stages.

Example:

Discovery
    ↓
Reconnaissance
    ↓
Command And Control

MITRE techniques and tactics remain available as supporting context, while attack stages represent the actual correlated sequence.

If a correlation does not have an authentic attack chain, the backend does not fabricate one.

🚨 Incident Management

Incidents combine risk, correlation, enrichment, and analyst-oriented context.

An incident can contain:

incident_id
risk_score
risk_level
priority
related_events
attack_chain
reasons
recommendations
status

Incident Lifecycle

Open
  │
  ▼
Investigating
  │
  ▼
Resolved

An optional:

False Positive

status can also be used when applicable.

🧠 Explainability

The backend provides supporting reasons for the calculated risk.

Explainability is derived from the same approved risk calculation used by the risk engine rather than maintaining a separate hard-coded explanation system.

This helps the frontend answer:

Why did this incident receive this risk score?

📋 Response Recommendations

Recommendations are associated with individual incidents and are designed to support analyst investigation.

The recommendation API provides incident-specific guidance based on the available risk and threat context.

🔌 REST API

Risk

Calculate Risk

POST /api/v1/risk/calculate

Calculates the risk for an event using the approved risk model.

High-Risk Events

GET /api/v1/risk/high

Returns high-risk events for prioritization.

Risk Summary

GET /api/v1/risk/summary

Returns risk-summary information for dashboard visualization.

Incidents

Get Incidents

GET /api/v1/incidents

Returns available incidents.

Get Incident

GET /api/v1/incidents/{incident_id}

Returns a specific incident and its investigation context.

Update Incident Status

PATCH /api/v1/incidents/{incident_id}/status

Updates the status of an incident.

Attack Chains

GET /api/v1/attack-chains

Returns available attack-chain information.

Recommendations

GET /api/v1/recommendations/{incident_id}

Returns recommendations for a specific incident.

🏗️ Backend Architecture

                         Frontend
                            │
                            │ REST API
                            ▼
                 ┌─────────────────────┐
                 │      app.py         │
                 │    API / CORS       │
                 └──────────┬──────────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
      Risk Services   Incident Services   Intelligence
             │              │              │
             ▼              ▼              ▼
       Risk Engine     Repository      IOC / MITRE
             │              │          Correlation
             │              │          Attack Chain
             └──────────────┼──────────────┘
                            ▼
                    MongoDB / JSON
                       Persistence

🗄️ Data & Persistence

The backend supports MongoDB-based incident persistence.

Configuration includes:

Database: threat_detection
Collection: incidents

The repository layer provides MongoDB access with JSON backup/fallback behavior for local development and resilience.



