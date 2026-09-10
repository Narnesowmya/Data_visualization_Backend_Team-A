# Milestone 3 - Task 8 & Task 9

## Purpose
This package implements **Event Correlation (Task 8)** and **Attack Chain Identification (Task 9)** using the updated Task 6 + Task 7 outputs.

## Key correction: short correlation window
The primary **same-asset** correlation rule is now constrained to a **30-minute maximum gap between consecutive events**. Events for the same asset that are separated by more than 30 minutes are split into separate groups and cannot form one correlation or attack chain.

This directly follows the team's design requirement to check time proximity when creating correlation groups. The design specifies same user/source/asset relationships plus a short time window.

## Task 8 rules
1. Same asset + consecutive events within 30 minutes.
2. Same user + 30 minutes when `user_id` exists.
3. Repeated suspicious source IP + 30 minutes when repeated IPs exist.

The supplied 10,000-event dataset does not provide `user_id`, and repeated source IP relationships are not available at useful scale, so **same asset + time window is the primary demonstrated rule**.

## Task 4 MITRE integration
MITRE technique/tactic context is derived from the approved Task 4 file `enriched_security_events_mitre_mapped.csv` and stored in the compact `task4_mitre_context.csv`. No separate hardcoded event-type → MITRE technique map is maintained.

## Task 9 logic
A correlation becomes an attack chain only when at least **two distinct MITRE tactics/stages** are represented. Events are already time-ordered within each correlation. Task 7 `risk_score` and `risk_level` are inherited; the Task 6 risk formula is not recalculated. This matches the team's integration rule.

## Results from the updated 10,000-event dataset
- Input events: **10,000**
- Task 8 correlations: **5**
- Task 9 multi-stage attack chains: **2**
- Maximum correlation window: **25 minutes**

The lower correlation count is expected after removing same-asset events that were days apart; this is intentional and prevents unrelated events from being grouped into one attack chain.

## Files
- `event_correlation.py` — Task 8 time-window correlation
- `attack_chain.py` — Task 9 attack-chain identification
- `run_pipeline.py` — end-to-end execution
- `test_correlation.py` — tests including the >30-minute negative case
- `task4_mitre_context.csv` — compact MITRE context derived from approved Task 4
- `m3_task1_inputs.csv` — Task 6/7 event input
- `Task7_Prioritization_Input_Output.csv` — Task 7 output
- `prioritized_incidents.csv` — Task 7 prioritized output consumed by Task 9
- `correlations.csv/.json` — Task 8 output
- `attack_chains.csv/.json` — Task 9 output

## Run
```bash
python run_pipeline.py
```

## Test
```bash
python test_correlation.py
```

Expected: `3/3 tests passed`.
