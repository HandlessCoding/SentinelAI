"""Local health, model metadata, and prediction endpoints."""

from fastapi import APIRouter, Request

from backend.batch_processing import predict_records
from backend.request_limits import JSONRequestRoute
from backend.schemas import (
    ErrorResponse,
    HealthResponse,
    ModelInfo,
    PredictRequest,
    PredictResponse,
)
from ml.inference import FEATURE_TYPES

router = APIRouter(route_class=JSONRequestRoute)


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
