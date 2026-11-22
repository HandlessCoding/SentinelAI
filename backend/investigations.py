"""Store suspected-attack alerts and support analyst investigation workflows."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from backend.batch_processing import predict_records, request_digest
from backend.database import get_session
from backend.investigation_schemas import (
    AlertInfo, AlertStatus, AnalysisReceipt, IncidentCreate, IncidentInfo,
    IncidentUpdate, NoteCreate, NoteInfo,
)
from backend.models import Alert, AnalystNote, Incident, PredictionBatch
from backend.request_limits import JSONRequestRoute
from backend.schemas import ErrorResponse, PredictRequest


router = APIRouter(route_class=JSONRequestRoute)
Database = Annotated[Session, Depends(get_session)]
IdempotencyKey = Annotated[str, Header(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]


def receipt(batch, alert_ids):
    return AnalysisReceipt(
        batch_id=batch.id,
        record_count=batch.record_count,
        model_version=batch.model_version,
        decision_threshold=batch.decision_threshold,
        prediction_timestamp=batch.prediction_timestamp,
        alert_ids=alert_ids,
    )


def stored_receipt(db, batch, digest):
    if batch.request_sha256 != digest:
        raise HTTPException(status_code=409, detail="This idempotency key was used for a different batch.")
    alert_ids = db.scalars(select(Alert.id).where(Alert.batch_id == batch.id).order_by(Alert.record_index))
    return receipt(batch, list(alert_ids))


@router.post(
    "/analyze",
    response_model=AnalysisReceipt,
    status_code=201,
    responses={
        200: {"model": AnalysisReceipt, "description": "Replayed batch"},
        409: {"model": ErrorResponse, "description": "Idempotency key conflicts with a previous batch"},
        503: {"model": ErrorResponse, "description": "Database temporarily unavailable"},
    },
)
def analyze(batch: PredictRequest, request: Request, response: Response, db: Database,
            idempotency_key: IdempotencyKey):
    """Analyze prepared records and save one alert for each suspected attack."""
    digest = request_digest(batch.records)
    by_key = select(PredictionBatch).where(PredictionBatch.idempotency_key == idempotency_key)
    existing = db.scalar(by_key)
    if existing is not None:
        response.status_code = 200
        return stored_receipt(db, existing, digest)

    model = request.app.state.model
    predictions = predict_records(model, batch.records)
    created = db.scalar(
        insert(PredictionBatch)
        .values(
            idempotency_key=idempotency_key,
            request_sha256=digest,
            record_count=len(batch.records),
            model_version=model.model_version,
            decision_threshold=model.decision_threshold,
            prediction_timestamp=datetime.now(UTC),
        )
        .on_conflict_do_nothing(constraint="uq_prediction_batches_idempotency_key")
        .returning(PredictionBatch)
    )
    if created is None:
        # A concurrent insertion won and committed. Read its receipt.
        response.status_code = 200
        return stored_receipt(db, db.scalars(by_key).one(), digest)

    alerts = [
        Alert(batch_id=created.id, record_index=index, attack_probability=prediction["attack_probability"])
        for index, prediction in enumerate(predictions)
        if prediction["label"] == 1
    ]
    db.add_all(alerts)
    db.flush()
    result = receipt(created, [alert.id for alert in alerts])
    db.commit()
    return result


def alert_query():
    return (
        select(Alert, PredictionBatch.model_version, PredictionBatch.prediction_timestamp, Incident.status)
        .join(PredictionBatch, Alert.batch_id == PredictionBatch.id)
        .outerjoin(Incident, Alert.incident_id == Incident.id)
    )


def alert_info(row):
    alert, model_version, timestamp, status = row
    return AlertInfo(
        id=alert.id,
        batch_id=alert.batch_id,
        record_index=alert.record_index,
        attack_probability=alert.attack_probability,
        model_version=model_version,
        prediction_timestamp=timestamp,
        investigation_status=status or "unreviewed",
        incident_id=alert.incident_id,
    )


@router.get("/alerts", response_model=list[AlertInfo])
def list_alerts(
    db: Database, status: AlertStatus | None = None, batch_id: UUID | None = None,
    min_probability: Annotated[float | None, Query(ge=0, le=1)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    query = alert_query().order_by(PredictionBatch.prediction_timestamp.desc(), Alert.id)
    if status == "unreviewed":
        query = query.where(Alert.incident_id.is_(None))
    elif status is not None:
        query = query.where(Incident.status == status)
    if batch_id is not None:
        query = query.where(Alert.batch_id == batch_id)
    if min_probability is not None:
        query = query.where(Alert.attack_probability >= min_probability)
    return [alert_info(row) for row in db.execute(query.limit(limit).offset(offset))]


@router.get("/alerts/{alert_id}", response_model=AlertInfo)
def get_alert(alert_id: UUID, db: Database):
    row = db.execute(alert_query().where(Alert.id == alert_id)).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert_info(row)


def find_incident(db, incident_id, *, lock=False):
    incident = db.get(Incident, incident_id, with_for_update=lock)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


def incident_info(db, incident):
    alert_ids = db.scalars(select(Alert.id).where(Alert.incident_id == incident.id).order_by(Alert.id))
    notes = db.scalars(
        select(AnalystNote).where(AnalystNote.incident_id == incident.id)
        .order_by(AnalystNote.created_at, AnalystNote.id)
    )
    return IncidentInfo(
        id=incident.id, title=incident.title, description=incident.description,
        status=incident.status, created_at=incident.created_at, updated_at=incident.updated_at,
        alert_ids=list(alert_ids), notes=[NoteInfo.model_validate(note) for note in notes],
    )


@router.post("/incidents", response_model=IncidentInfo, status_code=201)
def create_incident(body: IncidentCreate, db: Database):
    alerts = list(db.scalars(
        select(Alert).where(Alert.id.in_(body.alert_ids)).order_by(Alert.id).with_for_update()
    ))
    if len(alerts) != len(body.alert_ids):
        raise HTTPException(status_code=404, detail="One or more alerts were not found.")
    if any(alert.incident_id is not None for alert in alerts):
        raise HTTPException(status_code=409, detail="One or more alerts already belong to an incident.")
    incident = Incident(title=body.title, description=body.description)
    db.add(incident)
    db.flush()
    for alert in alerts:
        alert.incident_id = incident.id
    result = incident_info(db, incident)
    db.commit()
    return result


@router.get("/incidents/{incident_id}", response_model=IncidentInfo)
def get_incident(incident_id: UUID, db: Database):
    return incident_info(db, find_incident(db, incident_id))


@router.patch("/incidents/{incident_id}", response_model=IncidentInfo)
def update_incident(incident_id: UUID, body: IncidentUpdate, db: Database):
    incident = find_incident(db, incident_id, lock=True)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
    incident.updated_at = datetime.now(UTC)
    result = incident_info(db, incident)
    db.commit()
    return result


@router.post("/incidents/{incident_id}/notes", response_model=NoteInfo, status_code=201)
def add_note(incident_id: UUID, body: NoteCreate, db: Database):
    find_incident(db, incident_id)
    note = AnalystNote(incident_id=incident_id, author=body.author, text=body.text)
    db.add(note)
    db.flush()
    result = NoteInfo.model_validate(note)
    db.commit()
    return result
