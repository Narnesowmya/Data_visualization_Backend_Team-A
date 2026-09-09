import os
from pathlib import Path
from dotenv import load_dotenv


from pydantic import ConfigDict
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR.parent / ".env")

class Settings(BaseSettings):
    PROJECT_NAME: str = "Security Intelligence & Decision Making Platform (Milestone 3)"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Support both the team's variable name and the M3 variable name.
    MONGO_URI: str = os.getenv(
        "MONGODB_URI",
        os.getenv("MONGO_URI", "mongodb://localhost:27017")
    )

    DATABASE_NAME: str = os.getenv(
        "MONGODB_DB_NAME",
        os.getenv("DATABASE_NAME", "ThreatDashboardDB")
    )

    INCIDENTS_COLLECTION: str = "incidents"
    PREDICTIONS_COLLECTION: str = "threat_predictions"

    DATA_DIR: Path = BASE_DIR / "data"
    INCIDENTS_JSON_PATH: Path = DATA_DIR / "incidents.json"
    PRIORITIZED_INCIDENTS_CSV: Path = DATA_DIR / "prioritized_incidents.csv"
    CORRELATIONS_JSON: Path = DATA_DIR / "correlations.json"
    ATTACK_CHAINS_JSON: Path = DATA_DIR / "attack_chains.json"
    RISK_SCORES_JSON: Path = DATA_DIR / "risk_scores.json"

    model_config = ConfigDict(case_sensitive=True)


settings = Settings()