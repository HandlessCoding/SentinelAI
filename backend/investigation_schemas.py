"""Contracts for persisted prediction batches and analyst investigations."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from backend.schemas import MAX_BATCH_SIZE

IncidentStatus = Literal["open", "investigating", "resolved"]
AlertStatus = Literal["unreviewed", "open", "investigating", "resolved"]
Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160, pattern=r"^[^\x00]+$")]
Author = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80, pattern=r"^[^\x00]+$")]
NoteText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000, pattern=r"^[^\x00]+$")]


class AnalysisReceipt(BaseModel):
    batch_id: UUID
    record_count: int
    model_version: str
    decision_threshold: float
    prediction_timestamp: datetime
    alert_ids: list[UUID]


class AlertInfo(BaseModel):
    id: UUID
    batch_id: UUID
    record_index: int
    classification: Literal["suspected_attack"] = "suspected_attack"
    attack_probability: float
    model_version: str
    prediction_timestamp: datetime
    investigation_status: AlertStatus
    incident_id: UUID | None


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Title
    description: NoteText | None = None
    alert_ids: list[UUID] = Field(min_length=1, max_length=MAX_BATCH_SIZE)

    @model_validator(mode="after")
    def reject_duplicate_alerts(self):
        if len(set(self.alert_ids)) != len(self.alert_ids):
            raise ValueError("Alert IDs must be unique")
        return self


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Title | None = None
    description: NoteText | None = None
    status: IncidentStatus | None = None

    @model_validator(mode="after")
    def validate_patch(self):
        if not self.model_fields_set:
            raise ValueError("Provide at least one incident field")
        for name in self.model_fields_set & {"title", "status"}:
            if getattr(self, name) is None:
                raise ValueError(f"{name} must not be null")
        return self


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    author: Author
    text: NoteText


class NoteInfo(NoteCreate):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    created_at: datetime


class IncidentInfo(BaseModel):
    id: UUID
    title: str
    description: str | None
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    alert_ids: list[UUID]
    notes: list[NoteInfo]
