"""JSON request and response contracts for the local API."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ml.inference import FEATURE_TYPES

MAX_BATCH_SIZE = 100
example_values = {
    "proto": "tcp", "service": "http", "state": "FIN",
    "dur": 0.12, "spkts": 8, "dpkts": 10, "sttl": 31, "dttl": 29,
}
example_record = {name: example_values.get(name, 0) for name in FEATURE_TYPES}


class PredictRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"records": [example_record]}]},
    )

    records: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=MAX_BATCH_SIZE,
        description="UNSW-NB15 predictor records. Feature validation uses the fitted model's schema.",
    )


class HealthResponse(BaseModel):
    status: Literal["ok"]


class ModelInfo(BaseModel):
    model_version: str
    expected_feature_count: int
    decision_threshold: float


class Prediction(BaseModel):
    label: Literal[0, 1]
    classification: Literal["normal", "attack"]
    attack_probability: float = Field(ge=0, le=1)


class PredictResponse(BaseModel):
    model_version: str
    decision_threshold: float
    predictions: list[Prediction]


class ErrorResponse(BaseModel):
    detail: str
