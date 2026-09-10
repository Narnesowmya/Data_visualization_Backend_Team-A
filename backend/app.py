from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Existing team/M2 routes
from routes import events, stats, threats, assets, vulnerabilities
from routes.debug import router as debug_router

# Existing MongoDB/index setup
from database.mongo import create_indexes

# Existing team M3 prediction API
from routes.prediction_api import router as prediction_api_router

# M3 Task 10/11 routes
from routes.risk_routes import router as risk_router
from routes.incident_routes import router as incident_router
from routes.intelligence_routes import router as intelligence_router
from routes.prediction_routes import router as prediction_router
from routes.anomaly_routes import router as anomaly_router


app = FastAPI(
    title="Threat Dashboard API",
    description=(
        "API serving security events, stats, threats, assets, vulnerabilities, "
        "risk prioritization, incidents, security intelligence, predictions, "
        "anomalies, attack chains, and response recommendations."
    ),
    version="1.0.0",
)


# Allow the frontend dashboard to call this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    # Existing team's MongoDB indexes.
    await create_indexes()


# Existing team/M2 routes
app.include_router(events.router)
app.include_router(stats.router)
app.include_router(threats.router)
app.include_router(assets.router)
app.include_router(vulnerabilities.router)
app.include_router(debug_router)

# Existing team M3 prediction API
app.include_router(prediction_api_router)

# M3 Task 10/11 routes
app.include_router(risk_router, prefix="/api/v1")
app.include_router(incident_router, prefix="/api/v1")
app.include_router(intelligence_router, prefix="/api/v1")
app.include_router(prediction_router, prefix="/api/v1")
app.include_router(anomaly_router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
def health_check():
    """Unauthenticated health check."""
    return {"status": "ok"}