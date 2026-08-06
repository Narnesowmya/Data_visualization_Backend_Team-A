from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import events, stats, threats, assets, vulnerabilities
from database.mongo import create_indexes

from routes.debug import router as debug_router

app = FastAPI(
    title="Threat Dashboard API",
    description="API serving security events, stats, threats, assets, and vulnerabilities.",
    version="1.0.0",
)

# Allow the frontend dashboard to call this API from the browser.
# Update allow_origins with your actual frontend URL when you have it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    # Creates MongoDB indexes for fast filtering/sorting, and a uniqueness
    # constraint on api_keys.key_hash. Safe to run every time the app starts.
    await create_indexes()


app.include_router(events.router)
app.include_router(stats.router)
app.include_router(threats.router)
app.include_router(assets.router)
app.include_router(vulnerabilities.router)
app.include_router(debug_router)


@app.get("/health", tags=["Health"])
def health_check():
    """Unauthenticated health check."""
    return {"status": "ok"}