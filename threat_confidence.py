import pandas as pd
import numpy as np
from pathlib import Path

# ============================================================
# TASK — THREAT CONFIDENCE SCORE
# ============================================================

INPUT_FILE = Path("data/threat_classification.csv")
OUTPUT_FILE = Path("data/threat_classification_with_confidence.csv")


# ------------------------------------------------------------
# Normalize numerical feature to 0–1
# ------------------------------------------------------------
def normalize(series):

    series = pd.to_numeric(
        series,
        errors="coerce"
    ).fillna(0)

    min_value = series.min()
    max_value = series.max()

    if max_value == min_value:
        return pd.Series(
            0.0,
            index=series.index
        )

    return (
        (series - min_value)
        / (max_value - min_value)
    ).clip(0, 1)


# ------------------------------------------------------------
# Convert binary security fields to 0/1
# ------------------------------------------------------------
def binary_value(series):

    values = (
        series
        .astype(str)
        .str.strip()
        .str.lower()
    )

    return values.isin([
        "1",
        "true",
        "yes",
        "y",
        "detected",
        "match",
        "matched"
    ]).astype(float)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():

    print("=" * 55)
    print("       THREAT CONFIDENCE SCORE")
    print("=" * 55)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"File not found: {INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    print("\nDataset loaded successfully!")
    print(f"Dataset shape: {df.shape}")

    # --------------------------------------------------------
    # Check required ML information
    # --------------------------------------------------------

    required_columns = [
        "prediction",
        "anomaly_score"
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:

        raise ValueError(
            f"Missing required columns: {missing}"
        )

    # --------------------------------------------------------
    # 1. Isolation Forest anomaly evidence
    # --------------------------------------------------------
    #
    # Lower Isolation Forest anomaly scores represent
    # stronger anomalous behaviour.
    # --------------------------------------------------------

    anomaly_score = pd.to_numeric(
        df["anomaly_score"],
        errors="coerce"
    ).fillna(0)

    minimum = anomaly_score.min()
    maximum = anomaly_score.max()

    if maximum != minimum:

        anomaly_evidence = (
            (maximum - anomaly_score)
            / (maximum - minimum)
        ).clip(0, 1)

    else:

        anomaly_evidence = pd.Series(
            0.0,
            index=df.index
        )

    # --------------------------------------------------------
    # 2. Security evidence
    # --------------------------------------------------------

    components = [
        anomaly_evidence
    ]

    weights = [
        0.40
    ]

    # Severity
    if "severity_score" in df.columns:

        components.append(
            normalize(df["severity_score"])
        )

        weights.append(0.15)

    # CVSS
    if "cvss_score" in df.columns:

        components.append(
            normalize(df["cvss_score"])
        )

        weights.append(0.15)

    # Failed login attempts
    if "failed_login_attempts" in df.columns:

        components.append(
            normalize(
                df["failed_login_attempts"]
            )
        )

        weights.append(0.10)

    # Event frequency
    if "event_frequency" in df.columns:

        components.append(
            normalize(
                df["event_frequency"]
            )
        )

        weights.append(0.10)

    # Alerts per user
    if "number_of_alerts_per_user" in df.columns:

        components.append(
            normalize(
                df["number_of_alerts_per_user"]
            )
        )

        weights.append(0.10)

    # --------------------------------------------------------
    # Binary security indicators
    # --------------------------------------------------------

    binary_features = [
        "malware_detected",
        "malicious_ip_flag",
        "threat_feed_match"
    ]

    for feature in binary_features:

        if feature in df.columns:

            components.append(
                binary_value(df[feature])
            )

            # Small additional evidence weight
            weights.append(0.025)

    # --------------------------------------------------------
    # Normalize weights
    # --------------------------------------------------------

    weights = np.array(weights)

    weights = (
        weights
        / weights.sum()
    )

    # --------------------------------------------------------
    # Calculate confidence
    # --------------------------------------------------------

    feature_matrix = np.column_stack(
        [
            component.to_numpy()
            for component in components
        ]
    )

    confidence_score = (
        feature_matrix @ weights
    ) * 100

    confidence_score = np.clip(
        confidence_score,
        0,
        100
    )

    df["threat_confidence_score"] = np.round(
        confidence_score,
        2
    )

    # --------------------------------------------------------
    # Confidence level
    # --------------------------------------------------------

    df["confidence_level"] = pd.cut(
        df["threat_confidence_score"],
        bins=[
            -0.01,
            39.99,
            69.99,
            84.99,
            100
        ],
        labels=[
            "Low",
            "Moderate",
            "High",
            "Very High"
        ]
    )

    # --------------------------------------------------------
    # Confidence reason
    # --------------------------------------------------------

    def generate_reason(index):

        reasons = []

        anomaly_value = (
            anomaly_evidence.iloc[index]
        )

        if anomaly_value >= 0.70:

            reasons.append(
                "strong anomaly evidence"
            )

        elif anomaly_value >= 0.40:

            reasons.append(
                "moderate anomaly evidence"
            )

        if (
            "severity_score" in df.columns
            and normalize(
                df["severity_score"]
            ).iloc[index] >= 0.70
        ):

            reasons.append(
                "high severity"
            )

        if (
            "cvss_score" in df.columns
            and normalize(
                df["cvss_score"]
            ).iloc[index] >= 0.70
        ):

            reasons.append(
                "high CVSS"
            )

        if (
            "failed_login_attempts"
            in df.columns
            and normalize(
                df["failed_login_attempts"]
            ).iloc[index] >= 0.70
        ):

            reasons.append(
                "high failed-login activity"
            )

        if (
            "event_frequency"
            in df.columns
            and normalize(
                df["event_frequency"]
            ).iloc[index] >= 0.70
        ):

            reasons.append(
                "high event frequency"
            )

        if "malware_detected" in df.columns:

            if (
                binary_value(
                    df["malware_detected"]
                ).iloc[index] == 1
            ):

                reasons.append(
                    "malware detected"
                )

        if "malicious_ip_flag" in df.columns:

            if (
                binary_value(
                    df["malicious_ip_flag"]
                ).iloc[index] == 1
            ):

                reasons.append(
                    "malicious IP enrichment"
                )

        if "threat_feed_match" in df.columns:

            if (
                binary_value(
                    df["threat_feed_match"]
                ).iloc[index] == 1
            ):

                reasons.append(
                    "threat-feed match"
                )

        if not reasons:

            reasons.append(
                "limited supporting security evidence"
            )

        return " + ".join(
            reasons[:4]
        )

    df["confidence_reason"] = [
        generate_reason(i)
        for i in range(len(df))
    ]

    # --------------------------------------------------------
    # Save result
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print("\n==========================================")
    print("Threat Confidence Score Results")
    print("==========================================")

    print(
        f"Minimum confidence : "
        f"{df['threat_confidence_score'].min():.2f}"
    )

    print(
        f"Maximum confidence : "
        f"{df['threat_confidence_score'].max():.2f}"
    )

    print(
        f"Mean confidence    : "
        f"{df['threat_confidence_score'].mean():.2f}"
    )

    print(
        f"Median confidence  : "
        f"{df['threat_confidence_score'].median():.2f}"
    )

    print("\nConfidence Distribution")
    print("------------------------------------------")

    print(
        df["confidence_level"]
        .value_counts()
        .sort_index()
    )

    print("\nSample Results")
    print("------------------------------------------")

    columns_to_show = [
        "prediction",
        "anomaly_score",
        "threat_confidence_score",
        "confidence_level",
        "confidence_reason"
    ]

    print(
        df[columns_to_show]
        .head(10)
        .to_string(index=False)
    )

    print("\nOutput saved to:")

    print(
        OUTPUT_FILE
    )

    print("\nTask completed successfully!")


# ------------------------------------------------------------
# Run
# ------------------------------------------------------------

if __name__ == "__main__":
    main()