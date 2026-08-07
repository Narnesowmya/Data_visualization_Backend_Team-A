# Cybersecurity Threat Detection Backend

Backend service for cybersecurity event analysis, threat intelligence enrichment, MITRE ATT&CK mapping, and MongoDB-based data storage.

This project was developed as part of **Data Visualization Backend Team-A** to support security analytics APIs and data preprocessing workflows.

## Features

* Security event APIs
* Threat intelligence APIs
* Asset and vulnerability APIs
* Statistics endpoints
* API key authentication
* MongoDB integration
* Data cleaning and preprocessing
* Feature engineering
* Threat enrichment
* MITRE ATT&CK mapping

## Technology Stack

* Python
* FastAPI
* MongoDB
* Motor / PyMongo

## Project Structure

```text
backend/
├── app.py
├── routes/
├── services/
├── database/
├── preprocessing/
├── models/
├── utils/
└── data/
```

## Setup

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload
```

API documentation will be available at:

```text
http://127.0.0.1:8000/docs
```



