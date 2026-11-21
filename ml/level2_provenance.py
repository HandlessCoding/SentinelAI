"""Preflight checks and native counter adapters for Level 2 development."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import product
import re
from typing import NamedTuple

from ml.level2_flow_schema import MAX_FLOW_VALUE, MAX_PROTOCOL, _parse_uint


# These names identify capture lineages, not interchangeable feature schemas.
RELEASE_LINEAGES = {
    "ton-iot-zeek": "ton-iot",
    "nf-ton-iot-v2": "ton-iot",
    "nf-ton-iot-v3": "ton-iot",
    "cicids2017-improved": "cic-ids2017",
    "lycos-ids2017": "cic-ids2017",
}
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class CaptureBlock:
    """One documented original capture block, with half-open time bounds.

    The caller verifies the evidence and supplies a stable parent capture ID.
    A digest, when available, identifies the original capture rather than its
    CSV export. Counts come from the eligible rows after the data audit.
    """

    release: str
    capture_id: str
    start: datetime
    end: datetime
    evidence: str
    benign: int
    attacks: int
    original_sha256: str | None = None

    def __post_init__(self):
        if self.release not in RELEASE_LINEAGES:
            raise ValueError("Release is outside the G17 development sources")
        if (not isinstance(self.capture_id, str) or not self.capture_id.strip()
                or self.capture_id != self.capture_id.strip()):
            raise ValueError("Use a nonempty canonical original capture ID")
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("A capture block needs a provenance reference")
        if not all(isinstance(time, datetime) and time.utcoffset() is not None
                   for time in (self.start, self.end)):
            raise ValueError("Capture bounds must be ordered and timezone-aware")
        start, end = self.start.astimezone(timezone.utc), self.end.astimezone(timezone.utc)
        if start >= end:
            raise ValueError("Capture bounds must be ordered and timezone-aware")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)
        if any(type(count) is not int or count < 0 for count in (self.benign, self.attacks)):
            raise ValueError("Class support must use nonnegative integer counts")
        if self.original_sha256 is not None and (
            not isinstance(self.original_sha256, str) or not _SHA256.fullmatch(self.original_sha256)
        ):
            raise ValueError("Invalid original capture SHA-256")

    @property
    def lineage(self):
        return RELEASE_LINEAGES[self.release]


@dataclass(frozen=True)
class BoundarySupport:
    fit_benign: int
    fit_attacks: int
    evaluation_benign: int
    evaluation_attacks: int
    shared_lineages: tuple[str, ...]


def check_capture_boundary(fit, evaluation, *, chronological=False,
                           require_distinct_lineages=False, require_attack_evaluation=True):
    """Check a proposed whole-capture boundary using caller-verified manifests.

    Use the exact-vector and verified session checks separately. This function
    checks declared metadata and support rather than verifying its evidence.
    """
    fit, evaluation = tuple(fit), tuple(evaluation)
    if not fit or not evaluation:
        raise ValueError("Both sides need capture blocks")
    for blocks in (fit, evaluation):
        keys = {(block.lineage, block.capture_id) for block in blocks}
        digests = [block.original_sha256.lower() for block in blocks if block.original_sha256]
        if len(keys) != len(blocks) or len(set(digests)) != len(digests):
            raise ValueError("A partition counts an original capture more than once")

    shared_lineages = {block.lineage for block in fit} & {block.lineage for block in evaluation}
    if require_distinct_lineages and shared_lineages:
        raise ValueError("The proposed cross-lineage boundary shares a capture lineage")
    for left, right in product(fit, evaluation):
        same_lineage = left.lineage == right.lineage
        if same_lineage and left.capture_id == right.capture_id:
            raise ValueError("The boundary shares an original capture ID")
        if (left.original_sha256 and right.original_sha256
                and left.original_sha256.lower() == right.original_sha256.lower()):
            raise ValueError("The boundary shares an original capture digest")
        if same_lineage and max(left.start, right.start) < min(left.end, right.end):
            raise ValueError("Capture times overlap within a shared lineage")
    if chronological and max(block.end for block in fit) > min(block.start for block in evaluation):
        raise ValueError("The fit captures must end before the evaluation starts")
    support = BoundarySupport(
        sum(block.benign for block in fit), sum(block.attacks for block in fit),
        sum(block.benign for block in evaluation), sum(block.attacks for block in evaluation),
        tuple(sorted(shared_lineages)),
    )
    if not support.fit_benign or not support.fit_attacks or not support.evaluation_benign:
        raise ValueError("Fit needs both classes and evaluation needs benign support")
    if require_attack_evaluation and not support.evaluation_attacks:
        raise ValueError("Attack recall requires verified attack support in evaluation")
    return support


def ton_v3_interval(row):
    """Decode v3's Unix milliseconds as UTC, preserving source precision."""
    fields = ("FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS")
    start, end = (_parse_uint(row.get(field), field, MAX_FLOW_VALUE) for field in fields)
    if end < start:
        raise ValueError("Flow end precedes its start")
    try:
        return (_UNIX_EPOCH + timedelta(milliseconds=start),
                _UNIX_EPOCH + timedelta(milliseconds=end))
    except OverflowError as error:
        raise ValueError("Flow timestamp is outside the supported UTC range") from error


class CicNativeCounters(NamedTuple):
    """The fixed CICFlowMeter contract, keeping native exporter semantics."""

    protocol: int
    duration_us: int
    forward_packets: int
    reverse_packets: int
    forward_payload_octets: int
    reverse_payload_octets: int


CIC_COUNTER_COLUMNS = (
    "Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
    "Total Length of Fwd Packet", "Total Length of Bwd Packet",
)


def cic_native_counters(row):
    """Read the documented fixed exporter columns without constructing flow-core-v1."""
    limits = (MAX_PROTOCOL,) + (MAX_FLOW_VALUE,) * 5
    return CicNativeCounters(*(
        _parse_uint(row.get(field), field, maximum)
        for field, maximum in zip(CIC_COUNTER_COLUMNS, limits, strict=True)
    ))
