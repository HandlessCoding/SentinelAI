"""Read Zeek flows, source health and rule findings from local PostgreSQL."""

from base64 import b64decode, urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, computed_field, field_serializer, field_validator
from sqlalchemy import func, select, text, tuple_
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


class CursorFlowPage(FlowPage):
    page_cursor: str
    next_cursor: str | None


class FlowCursor(BaseModel):
    scope: str
    snapshot: Annotated[str, Field(max_length=4096, pattern=r"^[0-9]{1,20}:[0-9]{1,20}:([0-9]{1,20}(,[0-9]{1,20})*)?$")]
    after: tuple[Annotated[int, Field(ge=0, le=2**63 - 1)], UUID] | tuple[AwareDatetime, UUID] | None = None

    @field_validator("snapshot")
    @classmethod
    def validate_snapshot(cls, value):
        lower, upper, active = value.split(":")
        lower, upper = int(lower), int(upper)
        running = [int(item) for item in active.split(",")] if active else []
        if not (3 <= lower <= upper < 2**64) or running != sorted(set(running)) or any(
            not lower <= xid < upper for xid in running
        ):
            raise ValueError("invalid PostgreSQL snapshot")
        return value

    def encode(self):
        return urlsafe_b64encode(self.model_dump_json().encode()).decode()


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
    last_drained_file: str | None
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
            last_drained_file=stream.last_drained_file,
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


@router.get("/flows", response_model=CursorFlowPage | FlowPage)
def list_flows(
    db: Database, protocol: Protocol | None = None,
    capture_id: Annotated[str | None, Query(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")] = None,
    connection_state: Annotated[str | None, Query(pattern=STATE_PATTERN)] = None,
    has_finding: bool | None = None,
    source: FlowSource | None = None,
    order: Literal["observed", "ingested"] = "observed",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
    pagination: Literal["offset", "cursor"] = "offset",
    cursor: Annotated[str | None, Query(min_length=1, max_length=6000)] = None,
):
    query = select(ZeekFlow).options(joinedload(ZeekFlow.capture))
    order_key = ZeekFlow.timestamp_ns
    if order == "ingested":
        order_key = ZeekFlow.ingested_at
        query = query.where(order_key.is_not(None))
    query = query.order_by(order_key.desc(), ZeekFlow.id.desc())
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
    if pagination == "cursor":
        if offset:
            raise HTTPException(status_code=422, detail="Cursor pagination does not accept a nonzero offset.")
        scope = sha256(json.dumps([order, protocol, capture_id, connection_state, has_finding, source, limit]).encode()).hexdigest()
        return list_cursor_page(db, query, order_key, order, scope, cursor, limit)
    if cursor is not None:
        raise HTTPException(status_code=422, detail="Select cursor pagination to use a cursor.")
    rows = list(db.scalars(query.limit(limit + 1).offset(offset)))
    next_offset = offset + limit if len(rows) > limit and offset + limit <= MAX_OFFSET else None
    return FlowPage(flows=[FlowInfo.model_validate(row) for row in rows[:limit]], next_offset=next_offset)


def list_cursor_page(db, query, order_key, order, scope, cursor, limit):
    if cursor is None:
        snapshot = db.scalar(text("SELECT pg_current_snapshot()::text"))
        try:
            marker = FlowCursor(scope=scope, snapshot=snapshot)
        except ValueError:
            raise HTTPException(status_code=503, detail="Could not start stable flow browsing. Retry the request.") from None
    else:
        try:
            marker = FlowCursor.model_validate_json(b64decode(cursor, altchars=b"-_", validate=True))
            if marker.scope != scope or (
                marker.after is not None and (order == "observed") != isinstance(marker.after[0], int)
            ):
                raise ValueError("cursor does not match the requested page")
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid cursor for these traffic filters and order.") from None

    # The snapshot excludes transactions that commit after the first page, even
    # when they insert older observed timestamps or tie an existing sort key.
    query = query.where(text("pg_visible_in_snapshot(zeek_flows.insert_xid::xid8, CAST(:snapshot AS pg_snapshot))")
                        .bindparams(snapshot=marker.snapshot))
    if marker.after is not None:
        query = query.where(tuple_(order_key, ZeekFlow.id) < tuple_(*marker.after))
    rows = list(db.scalars(query.limit(limit + 1)))
    next_cursor = None
    if len(rows) > limit:
        boundary = rows[limit - 1]
        key = boundary.timestamp_ns if order == "observed" else boundary.ingested_at
        next_cursor = marker.model_copy(update={"after": (key, boundary.id)}).encode()
    return CursorFlowPage(flows=[FlowInfo.model_validate(row) for row in rows[:limit]], next_offset=None,
                          page_cursor=marker.encode(), next_cursor=next_cursor)


@router.get("/flows/{flow_id}", response_model=FlowDetail)
def get_flow(flow_id: UUID, db: Database):
    flow = db.get(ZeekFlow, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="Flow not found.")
    return FlowDetail.model_validate(flow)
