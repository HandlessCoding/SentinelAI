"""Shared prediction and request fingerprinting for prepared network batches."""

from hashlib import sha256
import json
import logging

from fastapi import HTTPException

from ml.inference import InputValidationError, OPTIONAL_METADATA_COLUMNS


# Keep the prediction logger name stable across the route refactor.
logger = logging.getLogger("backend.routes")


def request_digest(records):
    """Hash the ordered records without optional dataset metadata."""
    predictors = [
        {name: value for name, value in record.items() if name not in OPTIONAL_METADATA_COLUMNS}
        for record in records
    ]
    try:
        canonical = json.dumps(predictors, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except ValueError:
        raise HTTPException(status_code=422, detail="Records must contain finite values.") from None
    return sha256(canonical.encode("utf-8")).hexdigest()


def predict_records(model, records):
    """Score validated-format records and expose sanitized API errors."""
    try:
        return model.predict(records)
    except InputValidationError:
        raise HTTPException(
            status_code=422, detail="Records must match the expected UNSW-NB15 feature schema."
        ) from None
    except Exception as error:
        logger.error("Prediction failed (%s)", type(error).__name__)
        raise HTTPException(status_code=500, detail="Prediction failed.") from None
