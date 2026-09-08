from datetime import datetime, timezone
from mongodb import get_database


def save_prediction(prediction):
    db = get_database()
    collection = db["threat_predictions"]

    prediction["prediction_timestamp"] = datetime.now(timezone.utc)

    result = collection.update_one(
        {"event_id": prediction["event_id"]},
        {"$set": prediction},
        upsert=True
    )

    if result.upserted_id:
        return str(result.upserted_id)

    return prediction["event_id"]


def get_predictions():
    db = get_database()
    collection = db["threat_predictions"]

    predictions = list(
        collection.find({}, {"_id": 0})
    )

    return predictions