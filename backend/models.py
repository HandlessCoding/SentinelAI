"""Relational records for prediction batches and analyst investigations."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, DateTime, Double, ForeignKey, Index, String, Text,
    UniqueConstraint, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


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


class ZeekCapture(Base):
    __tablename__ = "zeek_captures"
    __table_args__ = (
        UniqueConstraint("pcap_sha256", name="uq_zeek_captures_pcap_sha256"),
        UniqueConstraint("conn_sha256", name="uq_zeek_captures_conn_sha256"),
        CheckConstraint(
            "(source IN ('authorized_lab', 'authorized_archive') AND flow_count BETWEEN 1 AND 10000 "
            "AND pcap_sha256 IS NOT NULL AND conn_sha256 IS NOT NULL) OR "
            "(source IN ('recorded_replay', 'connected_sensor') AND flow_count >= 0 "
            "AND pcap_sha256 IS NULL AND conn_sha256 IS NULL)", name="ck_zeek_captures_provenance",
        ),
    )

    capture_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64))
    environment_id: Mapped[str] = mapped_column(String(64))
    observation_point: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(24))
    zeek_version: Mapped[str] = mapped_column(String(128))
    pcap_sha256: Mapped[str | None] = mapped_column(String(64))
    conn_sha256: Mapped[str | None] = mapped_column(String(64))
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    flow_count: Mapped[int] = mapped_column(BigInteger)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ZeekFlow(Base):
    __tablename__ = "zeek_flows"
    __table_args__ = (
        UniqueConstraint("capture_id", "source_row", name="uq_zeek_flows_source_row"),
        UniqueConstraint("capture_id", "stream_key", name="uq_zeek_flows_stream_key"),
        CheckConstraint("source_row > 0 AND timestamp_ns >= 0", name="ck_zeek_flows_provenance"),
        CheckConstraint("ground_truth IN ('benign', 'attack', 'unknown')", name="ck_zeek_flows_ground_truth"),
        Index("ix_zeek_flows_order", "timestamp_ns", "id"),
        Index("ix_zeek_flows_ingested", "ingested_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    capture_id: Mapped[str] = mapped_column(ForeignKey("zeek_captures.capture_id"))
    source_row: Mapped[int] = mapped_column(BigInteger)
    stream_key: Mapped[str | None] = mapped_column(String(64))
    source_file: Mapped[str | None] = mapped_column(String(64))
    source_offset: Mapped[int | None] = mapped_column(BigInteger)
    ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timestamp_ns: Mapped[int] = mapped_column(BigInteger)
    proto: Mapped[str] = mapped_column(String(24))
    conn_state: Mapped[str | None] = mapped_column(String(24))
    service: Mapped[str | None] = mapped_column(String(1024))
    history: Mapped[str | None] = mapped_column(String(1024))
    orig_host: Mapped[str | None] = mapped_column(String(45))
    resp_host: Mapped[str | None] = mapped_column(String(45))
    orig_port: Mapped[int | None]
    resp_port: Mapped[int | None]
    duration_ns: Mapped[int | None] = mapped_column(BigInteger)
    orig_pkts: Mapped[int | None] = mapped_column(BigInteger)
    resp_pkts: Mapped[int | None] = mapped_column(BigInteger)
    orig_ip_bytes: Mapped[int | None] = mapped_column(BigInteger)
    resp_ip_bytes: Mapped[int | None] = mapped_column(BigInteger)
    orig_bytes: Mapped[int | None] = mapped_column(BigInteger)
    resp_bytes: Mapped[int | None] = mapped_column(BigInteger)
    missed_bytes: Mapped[int | None] = mapped_column(BigInteger)
    ground_truth: Mapped[str] = mapped_column(String(8))
    label_category: Mapped[str | None] = mapped_column(String(64))
    label_reason: Mapped[str] = mapped_column(String(40))
    rule_code: Mapped[str | None] = mapped_column(String(32))
    capture: Mapped[ZeekCapture] = relationship()

    @property
    def observed_at(self):
        seconds, nanos = divmod(self.timestamp_ns, 10**9)
        timestamp = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
        return f"{timestamp:%Y-%m-%dT%H:%M:%S}.{nanos:09d}Z"

    @property
    def source(self):
        return self.capture.source


class ZeekStream(Base):
    __tablename__ = "zeek_streams"

    capture_id: Mapped[str] = mapped_column(ForeignKey("zeek_captures.capture_id"), primary_key=True)
    replay_capture_id: Mapped[str | None] = mapped_column(String(64))
    replay_conn_sha256: Mapped[str | None] = mapped_column(String(64))
    file_identity: Mapped[str | None] = mapped_column(String(64))
    byte_offset: Mapped[int] = mapped_column(BigInteger, default=0)
    anchor: Mapped[str | None] = mapped_column(String(64))
    discarding: Mapped[bool] = mapped_column(Boolean, default=False)
    rows_seen: Mapped[int] = mapped_column(BigInteger, default=0)
    rejected_rows: Mapped[int] = mapped_column(BigInteger, default=0)
    duplicate_rows: Mapped[int] = mapped_column(BigInteger, default=0)
    backlog_bytes: Mapped[int | None] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(24), default="starting")
    last_error: Mapped[str | None] = mapped_column(String(48))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    capture: Mapped[ZeekCapture] = relationship()
