"""Validate a bounded CSV upload and prepare it for the existing batch APIs."""

from io import StringIO
from itertools import batched
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from backend.batch_processing import request_digest
from backend.investigation_schemas import AnalysisReceipt
from backend.investigations import Database, stored_receipt
from backend.models import PredictionBatch
from backend.request_limits import MAX_JSON_BYTES, validate_body_headers
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


def _json_body_size(records):
    body = json.dumps({"records": records}, ensure_ascii=False, separators=(",", ":"))
    return len(body.encode("utf-8"))


def prepare_csv(payload: bytearray, *, require_deliverable: bool = True) -> CSVPreview:
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

    if require_deliverable:
        for index, record in enumerate(records, start=1):
            if _json_body_size([record]) > MAX_JSON_BYTES:
                raise HTTPException(status_code=413, detail=f"Record {index} exceeds the 2 MiB JSON request limit.")

    return CSVPreview(
        columns=columns,
        records=records,
        upload_id=request_digest(records),
        batch_size=MAX_BATCH_SIZE,
    )


async def _prepare_upload(request: Request, *, require_deliverable: bool = True) -> CSVPreview:
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
    return await run_in_threadpool(prepare_csv, payload, require_deliverable=require_deliverable)


CSV_INPUT = {"requestBody": {"required": True, "content": {"text/csv": {"schema": {
    "type": "string", "format": "binary",
}}}}}
CSV_ERRORS = {
    400: {"model": ErrorResponse, "description": "Invalid or interrupted request"},
    413: {"model": ErrorResponse, "description": "CSV byte, record, or encoded row limit exceeded"},
    415: {"model": ErrorResponse, "description": "Expected uncompressed text/csv"},
    422: {"model": ErrorResponse, "description": "Invalid CSV structure or predictor values"},
}


@router.post("/csv/preview", response_model=CSVPreview, responses=CSV_ERRORS, openapi_extra=CSV_INPUT)
async def preview_csv(request: Request):
    """Prepare UTF-8 CSV records without running the model or writing to the database."""
    return await _prepare_upload(request)


def _legacy_receipts(db, upload: CSVPreview):
    # Before the JSON cap, a complete row-count window could be saved even if
    # today it requires several JSON requests. Check that receipt before splitting.
    candidates = {
        f"csv-{upload.upload_id}-{index}": request_digest(records)
        for index, records in enumerate(batched(upload.records, upload.batch_size), start=1)
        if _json_body_size(records) > MAX_JSON_BYTES
    }
    if not candidates:
        return {}
    existing = db.scalars(select(PredictionBatch).where(PredictionBatch.idempotency_key.in_(candidates)))
    return {batch.idempotency_key: stored_receipt(db, batch, candidates[batch.idempotency_key]) for batch in existing}


@router.post(
    "/csv/receipts", response_model=dict[str, AnalysisReceipt], openapi_extra=CSV_INPUT,
    responses={
        **CSV_ERRORS,
        409: {"model": ErrorResponse, "description": "A previous batch has a different request digest"},
        503: {"model": ErrorResponse, "description": "Database temporarily unavailable"},
    },
)
async def csv_receipts(request: Request, db: Database):
    """Look up matching receipts for oversized windows saved before JSON limits."""
    upload = await _prepare_upload(request, require_deliverable=False)
    return await run_in_threadpool(_legacy_receipts, db, upload)
