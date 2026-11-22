"""Read imported Zeek flows and rule findings from local PostgreSQL."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_serializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database import get_session
from backend.models import ZeekFlow
from backend.zeek_rules import FINDING_EXPLANATIONS, STATE_PATTERN, Protocol


router = APIRouter(prefix="/traffic", tags=["Offline traffic"])
Database = Annotated[Session, Depends(get_session)]
MAX_OFFSET = 100_000


class RuleFinding(BaseModel):
    source: Literal["rule"] = "rule"
    code: str
    explanation: str


class FlowInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    capture_id: str
    source_row: int
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
    source: Literal["authorized_lab", "authorized_archive"]
    zeek_version: str
    imported_at: datetime
    pcap_sha256: str
    conn_sha256: str
    manifest_sha256: str


class FlowDetail(FlowInfo):
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
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
):
    query = select(ZeekFlow).order_by(ZeekFlow.timestamp_ns.desc(), ZeekFlow.id.desc())
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
