"""Read Zeek flows, source health and rule findings from local PostgreSQL."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_serializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from backend.database import get_session
from backend.models import ZeekCapture, ZeekFlow, ZeekStream
from backend.zeek_rules import FINDING_EXPLANATIONS, STATE_PATTERN, Protocol


router = APIRouter(prefix="/traffic", tags=["Network traffic"])
Database = Annotated[Session, Depends(get_session)]
MAX_OFFSET = 100_000
FlowSource = Literal["authorized_lab", "authorized_archive", "recorded_replay", "connected_sensor"]


class RuleFinding(BaseModel):
    source: Literal["rule"] = "rule"
    code: str
    explanation: str


class FlowInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    capture_id: str
    source_row: int
    source: FlowSource
    ingested_at: datetime | None
    observed_at: str
    proto: Protocol
    conn_state: str | None
    service: str | None
    orig_host: str | None
    resp_host: str | None
    orig_port: int | None
    resp_port: int | None
    ground_truth: Literal["benign", "attack", "unknown"]
    rule_code: str | None = Field(exclude=True)

    @computed_field
    @property
    def finding(self) -> RuleFinding | None:
        if self.rule_code is None:
            return None
        return RuleFinding(code=self.rule_code, explanation=FINDING_EXPLANATIONS[self.rule_code])


class CaptureInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    environment_id: str
    observation_point: str
    source: FlowSource
    zeek_version: str
    imported_at: datetime
    pcap_sha256: str | None
    conn_sha256: str | None
    manifest_sha256: str


class FlowDetail(FlowInfo):
    source_file: str | None
    source_offset: int | None
    history: str | None
    duration_ns: int | None
    orig_pkts: int | None
    resp_pkts: int | None
    orig_ip_bytes: int | None
    resp_ip_bytes: int | None
    orig_bytes: int | None
    resp_bytes: int | None
    missed_bytes: int | None
    label_category: str | None
    label_reason: str
    capture: CaptureInfo

    @field_serializer("duration_ns", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
                      "orig_bytes", "resp_bytes", "missed_bytes")
    def preserve_integer_precision(self, value: int | None) -> str | None:
        return None if value is None else str(value)


class FlowPage(BaseModel):
    flows: list[FlowInfo]
    next_offset: int | None


class ProtocolCount(BaseModel):
    protocol: Protocol
    count: int


class FlowSummary(BaseModel):
    total_flows: int
    finding_count: int
    protocols: list[ProtocolCount]


class StreamHealth(BaseModel):
    capture_id: str
    source: Literal["recorded_replay", "connected_sensor"]
    status: str
    backlog_bytes: int | None
    rejected_rows: int
    duplicate_rows: int
    last_error: str | None
    heartbeat_at: datetime | None
    last_success_at: datetime | None
    last_ingested_at: datetime | None
    replay_capture_id: str | None
    replay_conn_sha256: str | None


class MonitoringSummary(BaseModel):
    recent_flows: int
    recent_findings: int
    protocols: list[ProtocolCount]
    sources: list[StreamHealth]
    more_sources: bool


@router.get("/monitoring", response_model=MonitoringSummary)
def monitoring_summary(db: Database):
    now = datetime.now(UTC)
    counts = db.execute(select(ZeekFlow.proto, func.count(), func.count(ZeekFlow.rule_code))
                        .where(ZeekFlow.ingested_at >= now - timedelta(minutes=5))
                        .group_by(ZeekFlow.proto).order_by(ZeekFlow.proto)).all()
    streams = list(db.scalars(select(ZeekStream).options(joinedload(ZeekStream.capture))
                              .order_by(ZeekStream.capture_id).limit(101)))
    sources = []
    for stream in streams[:100]:
        stale = stream.heartbeat_at is None or stream.heartbeat_at < now - timedelta(seconds=15)
        sources.append(StreamHealth(
            capture_id=stream.capture_id, source=stream.capture.source,
            status="stale" if stale else stream.status,
            backlog_bytes=None if stale else stream.backlog_bytes,
            rejected_rows=stream.rejected_rows, duplicate_rows=stream.duplicate_rows,
            last_error=stream.last_error, heartbeat_at=stream.heartbeat_at,
            last_success_at=stream.last_success_at, last_ingested_at=stream.last_ingested_at,
            replay_capture_id=stream.replay_capture_id, replay_conn_sha256=stream.replay_conn_sha256,
        ))
    return MonitoringSummary(recent_flows=sum(n for _, n, _ in counts),
                             recent_findings=sum(n for _, _, n in counts),
                             protocols=[ProtocolCount(protocol=proto, count=n) for proto, n, _ in counts],
                             sources=sources, more_sources=len(streams) > 100)


@router.get("/summary", response_model=FlowSummary)
def traffic_summary(db: Database):
    counts = db.execute(select(
        ZeekFlow.proto, func.count(), func.count(ZeekFlow.rule_code),
    ).group_by(ZeekFlow.proto).order_by(ZeekFlow.proto)).all()
    return FlowSummary(
        total_flows=sum(count for _, count, _ in counts),
        finding_count=sum(count for _, _, count in counts),
        protocols=[ProtocolCount(protocol=proto, count=count) for proto, count, _ in counts],
    )


@router.get("/flows", response_model=FlowPage)
def list_flows(
    db: Database, protocol: Protocol | None = None,
    capture_id: Annotated[str | None, Query(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")] = None,
    connection_state: Annotated[str | None, Query(pattern=STATE_PATTERN)] = None,
    has_finding: bool | None = None,
    source: FlowSource | None = None,
    order: Literal["observed", "ingested"] = "observed",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
):
    query = select(ZeekFlow).options(joinedload(ZeekFlow.capture))
    if order == "ingested":
        query = query.where(ZeekFlow.ingested_at.is_not(None)).order_by(ZeekFlow.ingested_at.desc(), ZeekFlow.id.desc())
    else:
        query = query.order_by(ZeekFlow.timestamp_ns.desc(), ZeekFlow.id.desc())
    if source is not None:
        query = query.where(ZeekFlow.capture.has(ZeekCapture.source == source))
    if protocol is not None:
        query = query.where(ZeekFlow.proto == protocol)
    if capture_id is not None:
        query = query.where(ZeekFlow.capture_id == capture_id)
    if connection_state is not None:
        query = query.where(ZeekFlow.conn_state == connection_state)
    if has_finding is not None:
        query = query.where(ZeekFlow.rule_code.is_not(None) if has_finding else ZeekFlow.rule_code.is_(None))
    rows = list(db.scalars(query.limit(limit + 1).offset(offset)))
    next_offset = offset + limit if len(rows) > limit and offset + limit <= MAX_OFFSET else None
    return FlowPage(flows=[FlowInfo.model_validate(row) for row in rows[:limit]], next_offset=next_offset)


@router.get("/flows/{flow_id}", response_model=FlowDetail)
def get_flow(flow_id: UUID, db: Database):
    flow = db.get(ZeekFlow, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="Flow not found.")
    return FlowDetail.model_validate(flow)
