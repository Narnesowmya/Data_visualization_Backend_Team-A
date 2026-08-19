# Feature Selection for AI-Based Threat Detection & Anomaly Analysis Engine

## Objective

Identify the most relevant features from the Milestone-1 feature-engineered dataset (`feature_engineered_security_events_FIXED (3).csv`) for use in machine learning models designed for cybersecurity threat detection and anomaly analysis. The selected features were chosen based on their security relevance, availability in the processed dataset, and compatibility with unsupervised anomaly-detection algorithms.

---

## Selected Features

| Feature                   | Why selected                                                                                         | Data type   | Importance |
| ------------------------- | ---------------------------------------------------------------------------------------------------- | ----------- | ---------- |
| **event_type**            | Represents the category of security activity and helps distinguish different attack behaviors.       | Categorical | High       |
| **protocol**              | Network protocols are often associated with specific attack patterns and communication behaviors.    | Categorical | Medium     |
| **severity_score**        | Numeric measure of event severity that can be directly used by ML algorithms.                        | Numerical   | High       |
| **failed_login_attempts** | Strong indicator of brute-force and credential-based attacks.                                        | Numerical   | High       |
| **malware_detected**      | Direct signal of malware-related activity in the environment.                                        | Binary      | High       |
| **cvss_score**            | Indicates vulnerability severity and potential exposure level.                                       | Numerical   | High       |
| **os**                    | Provides operating-system context, which may influence attack likelihood and vulnerability patterns. | Categorical | Medium     |
| **department**            | Helps identify events targeting specific business units or organizational areas.                     | Categorical | Low–Medium |

---

## Excluded Features

The following features are excluded because they are identifiers, high-cardinality attributes, redundant fields, weak-signal fields, or potential leakage fields:

* event_id
* timestamp
* username
* source_ip
* destination_ip
* device_name
* asset_name
* vulnerability_id
* attack_type
* threat_indicator
* severity
* failed_login_count
* hour_of_day
* weekend_flag
* event_frequency
* malicious_ip_flag
* threat_feed_match
* number_of_alerts_per_user

### Reasons

* **Identifiers / high-cardinality:** event_id, username, source_ip, destination_ip, device_name, asset_name, vulnerability_id.
* **Potential leakage:** threat_indicator.
* **Redundant with selected features:** severity.
* **Not included in the final deployed model:** failed_login_count, hour_of_day, weekend_flag, event_frequency, malicious_ip_flag, threat_feed_match, number_of_alerts_per_user.
* **Not required for the initial anomaly-detection model:** attack_type.

---

## Final ML Feature Set

The following features are used in `ml_preprocessing.py` and `anomaly_detection.py`:

* event_type
* protocol
* severity_score
* failed_login_attempts
* malware_detected
* cvss_score
* os
* department

These features were selected because they provide meaningful security signals while keeping the preprocessing pipeline and anomaly-detection model relatively simple and efficient.

---

## Conclusion

The final feature set focuses on attack behavior, network communication patterns, event severity, authentication anomalies, malware activity, vulnerability risk, and system context. This compact set of eight features is fully aligned with the implemented preprocessing and model-training pipeline and is suitable for Isolation Forest, LOF, and One-Class SVM–based anomaly detection. The feature selection is intentionally designed to remain consistent with all subsequent Milestone-2 tasks, including preprocessing, model training, unsupervised evaluation, MongoDB prediction storage, and API-based inference workflows.
