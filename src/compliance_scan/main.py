"""FastAPI application entry point."""
from contextlib import asynccontextmanager
from fastapi import FastAPI

from .audit.db import init_db
from .api.scan import router as scan_router
from .api.compliance import router as compliance_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise SQLite schema on startup."""
    await init_db()
    yield


app = FastAPI(
    title="compliance-pre-scan",
    description="Local pre-upload compliance scanner — PII, secrets, anomalies, audit trail.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(scan_router)
app.include_router(compliance_router)


@app.get("/health", tags=["meta"])
async def health():
    return {"status": "ok", "version": "0.1.0"}
