from flask import Flask, jsonify
import pandas as pd

app = Flask(__name__)

# Read the dataset
df = pd.read_csv("../dataset/security_events.csv")

# API 1: Get all events
@app.route("/events", methods=["GET"])
def get_events():
    return jsonify(df.to_dict(orient="records"))

if __name__ == "__main__":
    app.run(debug=True)