"""Local health, model metadata, and prediction endpoints."""

import logging

from fastapi import APIRouter, HTTPException, Request

from backend.schemas import (
    ErrorResponse,
    HealthResponse,
    ModelInfo,
    PredictRequest,
    PredictResponse,
)
from ml.inference import FEATURE_TYPES, InputValidationError


router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/health", response_model=HealthResponse)
def health():
    """Check API availability."""
    return {"status": "ok"}


@router.get("/model/info", response_model=ModelInfo)
def model_info(request: Request):
    """Describe the loaded model's inference contract."""
    model = request.app.state.model
    return {
        "model_version": model.model_version,
        "expected_feature_count": len(FEATURE_TYPES),
        "decision_threshold": model.decision_threshold,
    }


@router.post(
    "/predict",
    response_model=PredictResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Malformed JSON"},
        422: {"model": ErrorResponse, "description": "Invalid batch or predictor records"},
        500: {"model": ErrorResponse, "description": "Prediction failed"},
    },
)
def predict(batch: PredictRequest, request: Request):
    """Score a batch with the model loaded at startup."""
    model = request.app.state.model
    return {
        "model_version": model.model_version,
        "decision_threshold": model.decision_threshold,
        "predictions": predict_records(model, batch.records),
    }


def predict_records(model, records):
    """Share the inference call and sanitized errors between both batch routes."""
    try:
        return model.predict(records)
    except InputValidationError:
        raise HTTPException(
            status_code=422, detail="Records must match the expected UNSW-NB15 feature schema."
        ) from None
    except Exception:
        logger.exception("Prediction failed")
        raise HTTPException(status_code=500, detail="Prediction failed.") from None
