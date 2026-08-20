from threat_predictions import save_prediction, get_predictions


prediction = {
    "event_id": "EVT002",
    "prediction": "Suspicious",
    "threat_type": "Brute Force",
    "confidence_score": 91,
    "anomaly_score": -0.72,
    "severity": "High",
    "model_version": "IF_v1"
}


try:
    inserted_id = save_prediction(prediction)

    print("Prediction stored successfully!")
    print("Inserted ID:", inserted_id)

except Exception as e:
    print("Failed to store prediction.")
    print("Error:", e)


print("\nStored predictions:")

try:
    predictions = get_predictions()

    for item in predictions:
        print(item)

except Exception as e:
    print("Failed to retrieve predictions.")
    print("Error:", e)