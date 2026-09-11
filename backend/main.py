"""AutoPatch Core Backend Application."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes.audit import router as audit_router
from backend.api.routes.context import router as context_router
from backend.api.routes.patch import router as patch_router
from backend.api.routes.retry import router as retry_router
from backend.api.routes.risk import router as risk_router
from backend.api.routes.scan import router as scan_router
from backend.api.routes.validation import router as validation_router
from backend.config import get_settings
from backend.database.database import init_db
from backend.models.vulnerability import HealthResponse

# Configure Logging
settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("autopatch")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager to initialize resources."""
    logger.info("Initializing AutoPatch database schema...")
    init_db()
    logger.info("AutoPatch initialization complete.")
    yield
    logger.info("AutoPatch shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    version="0.8.0",
    description="AutoPatch Agentic AI Automated Vulnerability Remediation Platform - Persistent Audit & Lineage",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routes
app.include_router(scan_router)
app.include_router(risk_router)
app.include_router(context_router)
app.include_router(patch_router)
app.include_router(validation_router)
app.include_router(retry_router)
app.include_router(audit_router)


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
    tags=["System"]
)
def health_check() -> HealthResponse:
    """Service health and liveness probe."""
    return HealthResponse(
        status="ok",
        service="autopatch",
        version="0.1.0"
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
