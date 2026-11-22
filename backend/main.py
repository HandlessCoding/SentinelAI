"""Create the FastAPI application and load the model during startup."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from backend.csv_uploads import router as csv_router
from backend.database import DatabaseConfigurationError
from backend.investigations import router as investigation_router
from backend.routes import router
from backend.schemas import MAX_BATCH_SIZE
from backend.traffic import router as traffic_router
from ml.inference import DEFAULT_ARTIFACT_DIR, FROZEN_PIPELINE_SHA256, load_model

logger = logging.getLogger(__name__)


def load_local_model():
    repository_root = Path(__file__).resolve().parents[1]
    return load_model(repository_root / DEFAULT_ARTIFACT_DIR, expected_pipeline_sha256=FROZEN_PIPELINE_SHA256)


def create_app(model_loader=load_local_model):
    @asynccontextmanager
    async def lifespan(app):
        app.state.model = model_loader()
        yield

    app = FastAPI(
        title="SentinelAI",
        description="Local UNSW-NB15 inference and offline Zeek traffic triage.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"], www_redirect=False
    )

    @app.exception_handler(RequestValidationError)
    async def handle_invalid_request(request: Request, error: RequestValidationError):
        issues = error.errors()
        if any(issue["type"] == "json_invalid" for issue in issues):
            return JSONResponse(status_code=400, content={"detail": "Malformed JSON."})
        if any(issue["loc"][:2] == ("header", "idempotency-key") for issue in issues):
            detail = "Provide a valid Idempotency-Key header."
        elif request.url.path in {"/predict", "/analyze"}:
            detail = f"Provide a records array with 1 to {MAX_BATCH_SIZE} objects."
        else:
            detail = "Invalid request fields or parameters."
        return JSONResponse(status_code=422, content={"detail": detail})

    @app.exception_handler(SQLAlchemyError)
    @app.exception_handler(DatabaseConfigurationError)
    async def handle_database_error(_request: Request, error: Exception):
        logger.error("Database request failed (%s)", type(error).__name__)
        return JSONResponse(status_code=503, content={"detail": "Database unavailable."})

    app.include_router(router)
    app.include_router(investigation_router)
    app.include_router(csv_router)
    app.include_router(traffic_router)
    return app


app = create_app()
