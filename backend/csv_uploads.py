"""Validate a bounded CSV upload and prepare it for the existing batch APIs."""

from io import StringIO

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from backend.batch_processing import request_digest
from backend.request_limits import validate_body_headers
from backend.schemas import ErrorResponse, MAX_BATCH_SIZE
from ml.inference import (
    FEATURE_TYPES, InputValidationError, read_prediction_rows, validated_batch,
)


router = APIRouter()
MAX_CSV_BYTES = 2 * 1024 * 1024
MAX_CSV_RECORDS = 1_000
SIZE_ERROR = "CSV files must be at most 2 MiB."


class CSVPreview(BaseModel):
    columns: list[str]
    records: list[dict[str, str]]
    upload_id: str
    batch_size: int


def prepare_csv(payload: bytearray) -> CSVPreview:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeError:
        raise HTTPException(status_code=422, detail="CSV files must use UTF-8 encoding.") from None
    if not text.strip():
        raise HTTPException(status_code=422, detail="The CSV is empty.")
    if "\x00" in text:
        raise HTTPException(status_code=422, detail="The CSV contains invalid null characters.")

    columns = list(FEATURE_TYPES)
    records = []
    try:
        with StringIO(text, newline="") as stream:
            for row in read_prediction_rows(stream, include_unexpected_names=False):
                if len(records) == MAX_CSV_RECORDS:
                    raise HTTPException(
                        status_code=413,
                        detail=f"CSV files must contain at most {MAX_CSV_RECORDS:,} records.",
                    )
                records.append({name: row[name] for name in columns})
        if not records:
            raise InputValidationError("Include at least one record below the CSV header.")
        validated_batch(records)
    except InputValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None

    return CSVPreview(
        columns=columns,
        records=records,
        upload_id=request_digest(records),
        batch_size=MAX_BATCH_SIZE,
    )


@router.post(
    "/csv/preview",
    response_model=CSVPreview,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid or interrupted request"},
        413: {"model": ErrorResponse, "description": "CSV byte or record limit exceeded"},
        415: {"model": ErrorResponse, "description": "Expected uncompressed text/csv"},
        422: {"model": ErrorResponse, "description": "Invalid CSV structure or predictor values"},
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"text/csv": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
async def preview_csv(request: Request):
    """Prepare UTF-8 CSV records without running the model or writing to the database."""
    validate_body_headers(
        request, media_type="text/csv", max_bytes=MAX_CSV_BYTES,
        media_error="Send an uncompressed CSV with Content-Type text/csv.",
        length_error="Invalid upload length.", size_error=SIZE_ERROR,
    )

    payload = bytearray()
    try:
        async for chunk in request.stream():
            if len(payload) + len(chunk) > MAX_CSV_BYTES:
                raise HTTPException(status_code=413, detail=SIZE_ERROR)
            payload.extend(chunk)
    except ClientDisconnect:
        raise HTTPException(status_code=400, detail="The CSV upload was interrupted.") from None
    return await run_in_threadpool(prepare_csv, payload)
