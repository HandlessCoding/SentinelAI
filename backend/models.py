"""Relational records for prediction batches and analyst investigations."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint, DateTime, Double, ForeignKey, Index, String, Text,
    UniqueConstraint, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class PredictionBatch(Base):
    __tablename__ = "prediction_batches"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_prediction_batches_idempotency_key"),
        CheckConstraint("record_count BETWEEN 1 AND 100", name="ck_prediction_batches_record_count"),
        CheckConstraint("decision_threshold BETWEEN 0 AND 1", name="ck_prediction_batches_threshold"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_sha256: Mapped[str] = mapped_column(String(64))
    record_count: Mapped[int]
    model_version: Mapped[str] = mapped_column(String(80))
    decision_threshold: Mapped[float] = mapped_column(Double)
    prediction_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("status IN ('open', 'investigating', 'resolved')", name="ck_incidents_status"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), server_default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("batch_id", "record_index", name="uq_alerts_batch_record"),
        CheckConstraint("record_index BETWEEN 0 AND 99", name="ck_alerts_record_index"),
        CheckConstraint("attack_probability BETWEEN 0 AND 1", name="ck_alerts_attack_probability"),
        Index("ix_alerts_incident_id", "incident_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    batch_id: Mapped[UUID] = mapped_column(ForeignKey("prediction_batches.id"))
    incident_id: Mapped[UUID | None] = mapped_column(ForeignKey("incidents.id"))
    record_index: Mapped[int]
    attack_probability: Mapped[float] = mapped_column(Double)


class AnalystNote(Base):
    __tablename__ = "analyst_notes"
    __table_args__ = (Index("ix_analyst_notes_incident_id", "incident_id"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id"))
    author: Mapped[str] = mapped_column(String(80))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
